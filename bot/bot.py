import signal
import sys
import asyncio
import os
import discord
from discord import app_commands
from discord.ui import TextInput, Modal
import random
from dotenv import load_dotenv
import resend
import logging
from pydantic import BaseModel, EmailStr, ValidationError
import time
from upstash_redis.asyncio import Redis
from upstash_ratelimit.asyncio import Ratelimit, FixedWindow
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# Load environment variables
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
resend.api_key = os.getenv("RESEND_API_KEY")
UPSTASH_REDIS_REST_URL = os.getenv("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")
HEALTHCHECK_PORT = int(os.getenv("PORT", 8000))

# Constants
VERIFICATION_CODE_LENGTH = 6
RATE_LIMIT_MAX_REQUESTS = 10
RATE_LIMIT_WINDOW = 600  # 10 minutes
VERIFICATION_CODE_EXPIRY = 600  # 10 minutes
EMAIL_DOMAIN = "@online.bits-pilani.ac.in"
BOT_EMAIL = "noreply@bits-bot.sattwyk.com"

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Upstash Redis setup
redis_client = Redis(url=UPSTASH_REDIS_REST_URL, token=UPSTASH_REDIS_REST_TOKEN)

# Upstash Ratelimit setup
ratelimit = Ratelimit(
    redis=redis_client,
    limiter=FixedWindow(max_requests=RATE_LIMIT_MAX_REQUESTS, window=RATE_LIMIT_WINDOW),
    prefix="@upstash/ratelimit",
)


class EmailInput(BaseModel):
    email: EmailStr

    @property
    def is_valid_bits_email(self):
        return self.email.endswith(EMAIL_DOMAIN)


class VerifyBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        await self.tree.sync()


discord_client = VerifyBot()


async def rate_limit_user(user_id: str):
    identifier = f"user:{user_id}"
    result = await ratelimit.limit(identifier)
    return result.allowed


def monitor_email_sending(total_sent, total_failed, duration):
    logger.info(
        f"Email Sending Metrics: Total Sent: {total_sent}, Total Failed: {total_failed}, Duration: {duration:.2f} seconds"
    )


class EmailModal(Modal):
    def __init__(self):
        super().__init__(title="BITS Pilani Email Verification")
        self.email = TextInput(
            label="Enter your BITS Pilani student email",
            placeholder=f"f20XXXXX{EMAIL_DOMAIN}",
            required=True,
        )
        self.add_item(self.email)

    async def on_submit(self, interaction: discord.Interaction):
        async def send_error_message(message: str):
            logger.error(message)
            await interaction.response.send_message(message, ephemeral=True)

        # Check rate limit
        if not await rate_limit_user(interaction.user.id):
            await send_error_message("Rate limit exceeded. Please try again later.")
            return

        # Validate email
        try:
            email_input = EmailInput(email=self.email.value)
        except ValidationError:
            await send_error_message("Please enter a valid email address.")
            return

        if not email_input.is_valid_bits_email:
            await send_error_message("Invalid BITS Pilani email")
            return

        # Generate verification code
        verification_code = "".join(
            str(random.randint(0, 9)) for _ in range(VERIFICATION_CODE_LENGTH)
        )

        # Send email
        params = {
            "from": f"BITS Discord Bot <{BOT_EMAIL}>",
            "to": [email_input.email],
            "subject": "Discord Verification Code",
            "html": f"Your verification code is: <strong>{verification_code}</strong>",
        }

        email_result = resend.Emails.send(params)
        if not email_result:
            await send_error_message(
                "Failed to send verification email. Please try again later."
            )
            return

        # Store verification code
        try:
            await redis_client.set(
                key=f"verify:{interaction.user.id}",
                value=f"{verification_code}:{email_input.email}",
                ex=VERIFICATION_CODE_EXPIRY,
            )
        except Exception:
            await send_error_message(
                "Failed to store verification code. Please try again."
            )
            return

        # Send success message
        await interaction.response.send_message(
            f"A verification code has been sent to {email_input.email}. Please use `/verify` again to enter the code.",
            ephemeral=True,
        )


class CodeModal(Modal):
    def __init__(self):
        super().__init__(title="Code Verification")
        self.code = TextInput(
            label="Enter the verification code", placeholder="123456", required=True
        )
        self.add_item(self.code)

    async def on_submit(self, interaction: discord.Interaction):
        async def send_error_message(message: str):
            logger.error(f"Code verification error: {message}")
            await interaction.response.send_message(message, ephemeral=True)

        # Get stored verification data
        stored_data = await redis_client.get(f"verify:{interaction.user.id}")
        if not stored_data:
            await send_error_message("Verification code expired or not found")
            return

        # Verify code
        entered_code = self.code.value
        try:
            correct_code, _ = stored_data.split(":")
        except Exception:
            await send_error_message("Invalid verification data stored")
            return

        if entered_code != correct_code:
            await send_error_message("Incorrect verification code")
            return

        # Get verified role
        verified_role = discord.utils.get(interaction.guild.roles, name="Verified")
        if not verified_role:
            await send_error_message("Verified role not found")
            return

        # Assign role and cleanup
        try:
            await interaction.user.add_roles(verified_role)
            await redis_client.delete(f"verify:{interaction.user.id}")
        except Exception:
            await send_error_message("Failed to assign verified role")
            return

        # Send success message
        await interaction.response.send_message(
            "Verification successful! You have been given the Verified role.",
            ephemeral=True,
        )


@discord_client.tree.command()
async def verify(interaction: discord.Interaction):
    """Start the verification process"""
    try:
        verified_role = discord.utils.get(interaction.guild.roles, name="Verified")
        if verified_role in interaction.user.roles:
            await interaction.response.send_message(
                "You are already verified!", ephemeral=True
            )
            return

        if await redis_client.exists(f"verify:{interaction.user.id}"):
            modal = CodeModal()
        else:
            modal = EmailModal()

        await interaction.response.send_modal(modal)

    except Exception as e:
        logger.error(f"Error in verify command: {str(e)}")
        await interaction.response.send_message(
            "An error occurred. Please try again later.", ephemeral=True
        )


@discord_client.event
async def on_ready():
    logger.info(f"Logged in as {discord_client.user}")


def signal_handler(sig, frame):
    logger.info(f"Received shutdown signal ({sig}), cleaning up...")
    asyncio.create_task(cleanup())


async def cleanup():
    logger.info("Performing cleanup...")
    try:
        await discord_client.close()
        await redis_client.close()
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
    logger.info("Cleanup complete, exiting...")


class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")


def start_health_check_server():
    server_address = ("", HEALTHCHECK_PORT)
    httpd = HTTPServer(server_address, HealthCheckHandler)
    logger.info(f"Starting health check server on port {HEALTHCHECK_PORT}")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()


async def main():
    try:
        start_health_check_server()
        logger.info("Starting health check server started")
    except Exception as e:
        logger.error(f"Failed to start health check server: {str(e)}")
        await cleanup()
        sys.exit(1)

    try:
        async with discord_client:
            await discord_client.start(DISCORD_TOKEN)
    except discord.LoginFailure:
        logger.error("Invalid token provided")
        await cleanup()
        sys.exit(1)
    except discord.HTTPException as e:
        logger.error(f"HTTP error occurred: {str(e)}")
        await cleanup()
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error in main: {str(e)}")
        await cleanup()
        sys.exit(1)


if __name__ == "__main__":
    start_time = time.time()
    total_sent = 0
    total_failed = 0

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGQUIT):
        signal.signal(sig, signal_handler)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.error("Interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
    finally:
        duration = time.time() - start_time
        monitor_email_sending(total_sent, total_failed, duration)
        asyncio.run(cleanup())
        sys.exit(0)
