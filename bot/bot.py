import signal
import sys
import asyncio
import os
import discord
from discord import app_commands
from discord.ui import TextInput, Modal, View, Button
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
HEALTHCHECK_PORT = int(os.getenv("PORT", 8080))

# Constants
OTP_LENGTH = 6
RATE_LIMIT_MAX_REQUESTS = 5
RATE_LIMIT_WINDOW = 600  # 10 minutes
OTP_EXPIRY = 600  # 10 minutes
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


async def rate_limit_user(user_id: str):
    identifier = f"user:{user_id}"
    result = await ratelimit.limit(identifier)
    return result.allowed


class EmailInput(BaseModel):
    email: EmailStr

    @property
    def is_valid_bits_email(self):
        return self.email.endswith(EMAIL_DOMAIN)


class EmailModal(Modal):
    def __init__(self):
        super().__init__(title="BITS Pilani Email Verification")
        self.email = TextInput(
            label="Enter your BITS Pilani student email",
            placeholder=f"202XXXXXX{EMAIL_DOMAIN}",
            required=True,
        )
        self.add_item(self.email)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)

        try:
            # if already has verified role then return
            verified_role = discord.utils.get(interaction.guild.roles, name="Verified")
            if verified_role in interaction.user.roles:
                await interaction.followup.send(
                    "You are already verified!", ephemeral=True
                )
                return

            if not await rate_limit_user(interaction.user.id):
                raise ValueError("Rate limit exceeded. Please try again later.")

            email_input = EmailInput(email=self.email.value)
            if not email_input.is_valid_bits_email:
                raise ValueError("Enter a valid BITS Pilani student email.")

            OTP = "".join(random.choices("0123456789", k=OTP_LENGTH))

            email_params = {
                "from": f"BITS Discord Bot <{BOT_EMAIL}>",
                "to": [email_input.email],
                "subject": "Discord Email Verification OTP",
                "html": f"Your OTP is: <strong>{OTP}</strong>",
            }

            if not resend.Emails.send(email_params):
                raise ValueError("Failed to send the OTP. Please try again later.")

            await redis_client.set(
                f"verify:{interaction.user.id}",
                f"{OTP}:{email_input.email}",
                ex=OTP_EXPIRY,
            )

            await interaction.followup.send(
                f"An OTP has been sent to **{email_input.email}**. \nNOTE: The code will expire in **10 minutes**. \nIf Enter OTP Button doesn't appear use `/verify` again",
                ephemeral=True,
            )

            await interaction.followup.send(
                view=VerifyView(email=False), ephemeral=True
            )

        except ValidationError as e:
            await interaction.followup.send("Enter a valid email.", ephemeral=True)
            logger.error(f"Validation error in EmailModal: {str(e)}")
        except ValueError as e:
            await interaction.followup.send(str(e), ephemeral=True)
            logger.error(f"Error in EmailModal: {str(e)}")
        except Exception as e:
            await interaction.followup.send(
                "An unexpected error occurred. Please try again later.", ephemeral=True
            )
            logger.error(f"Unexpected error in EmailModal: {str(e)}")


class OTPModal(Modal):
    """
    Modal dialog for OTP entry.
    Handles the verification process including role management and Redis operations.
    """

    def __init__(self):
        super().__init__(title="OTP Verification")
        self.code = TextInput(
            label="Enter the OTP",
            placeholder="xxxxxx",
            required=True,
            min_length=OTP_LENGTH,
            max_length=OTP_LENGTH,
        )
        self.add_item(self.code)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)

        try:
            # Check if user is already verified
            verified_role = discord.utils.get(interaction.guild.roles, name="Verified")
            if verified_role in interaction.user.roles:
                await interaction.followup.send(
                    "You are already verified!", ephemeral=True
                )
                return

            # Validate OTP from Redis
            stored_data = await redis_client.get(f"verify:{interaction.user.id}")
            if not stored_data:
                raise ValueError("OTP expired or not found")

            correct_code, _ = stored_data.split(":")
            if self.code.value != correct_code:
                raise ValueError("Incorrect OTP")

            # Remove UnVerified Role
            unverified_role = discord.utils.get(
                interaction.guild.roles, name="UnVerified"
            )

            if not unverified_role:
                raise ValueError("@UnVerified role not found")

            await interaction.user.remove_roles(unverified_role)

            # Add Verified Role
            verified_role = discord.utils.get(interaction.guild.roles, name="Verified")
            if not verified_role:
                raise ValueError("@Verified role not found")

            await interaction.user.add_roles(verified_role)

            # Remove UnVerified Role
            unverified_role = discord.utils.get(
                interaction.guild.roles, name="UnVerified"
            )

            if not unverified_role:
                raise ValueError("@UnVerified role not found")

            await interaction.user.remove_roles(unverified_role)

            # Cleanup and Success Message
            await redis_client.delete(f"verify:{interaction.user.id}")
            await interaction.followup.send(
                "Verification successful! You have been given the Verified role.",
                ephemeral=True,
            )

        except ValueError as e:
            # Handle validation errors
            await interaction.followup.send(str(e), ephemeral=True)
            logger.error(f"OTP verification error: {str(e)}")
        except Exception as e:
            # Handle unexpected errors
            await interaction.followup.send(
                "An unexpected error occurred. Please try again later.", ephemeral=True
            )
            logger.error(f"Unexpected error in OTPModal: {str(e)}")


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


class VerifyView(View):
    def __init__(self, email=True, code=True):
        super().__init__()
        if email:
            self.add_item(
                Button(
                    label="Enter Email",
                    custom_id="email_button",
                    style=discord.ButtonStyle.primary,
                )
            )
        if code:
            self.add_item(
                Button(
                    label="Enter OTP",
                    custom_id="otp_button",
                    style=discord.ButtonStyle.secondary
                    if email
                    else discord.ButtonStyle.primary,
                )
            )


@discord_client.tree.command()
async def verify(interaction: discord.Interaction):
    """Start the verification process"""
    await interaction.response.defer(ephemeral=True)
    try:
        verified_role = discord.utils.get(interaction.guild.roles, name="Verified")
        if verified_role in interaction.user.roles:
            await interaction.followup.send("You are already verified!", ephemeral=True)
            return

        view = VerifyView()
        await interaction.followup.send(
            "Hey There!\nChoose an option below to start the verification process:",
            view=view,
            ephemeral=True,
        )

    except discord.errors.NotFound:
        logger.error("Unknown interaction error occurred in verify command")
    except Exception as e:
        logger.error(f"Error in verify command: {str(e)}")
        await interaction.followup.send(
            "An error occurred. Please try again later.", ephemeral=True
        )


email_modal = EmailModal()
otp_modal = OTPModal()


@discord_client.event
async def on_interaction(interaction: discord.Interaction):
    if interaction.type == discord.InteractionType.component:
        if interaction.data["custom_id"] == "email_button":
            await interaction.response.send_modal(email_modal)
        elif interaction.data["custom_id"] == "otp_button":
            await interaction.response.send_modal(otp_modal)


@discord_client.event
async def on_ready():
    logger.info(f"Logged in as {discord_client.user}")


# Error handler for application command errors
@discord_client.tree.error
async def on_app_command_error(
    interaction: discord.Interaction, error: app_commands.AppCommandError
):
    if isinstance(error, app_commands.CommandOnCooldown):
        await interaction.response.send_message(
            f"This command is on cooldown. Try again in {error.retry_after:.2f} seconds.",
            ephemeral=True,
        )
    elif isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message(
            "You don't have the required permissions to use this command.",
            ephemeral=True,
        )
    else:
        logger.error(f"Unhandled application command error: {str(error)}")
        await interaction.response.send_message(
            "An error occurred while processing the command. Please try again later.",
            ephemeral=True,
        )


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


async def cleanup():
    logger.info("Performing cleanup...")
    try:
        await discord_client.close()
        await redis_client.close()
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
    logger.info("Cleanup complete, exiting...")


def monitor_email_sending(total_sent, total_failed, duration):
    logger.info(
        f"Email Sending Metrics: Total Sent: {total_sent}, Total Failed: {total_failed}, Duration: {duration:.2f} seconds"
    )


def signal_handler(sig, _):
    logger.info(f"Received shutdown signal ({sig}), cleaning up...")
    asyncio.create_task(cleanup())


if __name__ == "__main__":
    start_time = time.time()
    total_sent = 0
    total_failed = 0

    for sig in (
        signal.SIGINT,
        signal.SIGTERM,
        signal.SIGQUIT,
        signal.SIGHUP,
        signal.SIGUSR1,
        signal.SIGUSR2,
    ):
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
