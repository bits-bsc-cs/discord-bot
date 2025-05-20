import discord
import logging
from discord import TextInput, Modal
from discord.ui import View, Button
from github_utils import invite_to_github, check_github_rate_limit

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class GitHubUsernameModal(Modal):
    def __init__(self):
        super().__init__(title="GitHub Organization Invitation")
        self.username = TextInput(
            label="Your GitHub username",
            placeholder="Enter your GitHub username",
            required=True,
            min_length=1,
            max_length=39  # GitHub username max length
        )
        self.add_item(self.username)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)

        try:
            # Check if user is verified
            verified_role = discord.utils.get(interaction.guild.roles, name="Verified")
            if not verified_role or verified_role not in interaction.user.roles:
                logger.warning(f"User {interaction.user.id} attempted to join GitHub organization without verification")
                await interaction.followup.send("You must be verified to join the GitHub organization.", ephemeral=True)
                return

            # Check rate limit
            rate_limit_allowed = await check_github_rate_limit(str(interaction.user.id))
            if not rate_limit_allowed:
                logger.info(f"Rate limit exceeded for user {interaction.user.id}")
                await interaction.followup.send(
                    "You've exceeded the rate limit for GitHub invitations (3 per 24 hours). Please try again later.",
                    ephemeral=True
                )
                return

            # Process GitHub invitation
            username = self.username.value.strip()
            logger.debug(f"Processing GitHub invitation for username: {username}")
            
            # Basic username validation
            if not username or len(username) < 1:
                await interaction.followup.send("Please enter a valid GitHub username.", ephemeral=True)
                return
                
            # Invite user to GitHub organization
            result = await invite_to_github(username)
            
            if result["success"]:
                await interaction.followup.send(f"Success! {result['message']}", ephemeral=True)
            else:
                await interaction.followup.send(f"Error: {result['message']}", ephemeral=True)
                
        except Exception as e:
            logger.error(f"Error in GitHubUsernameModal: {str(e)}")
            await interaction.followup.send(
                "An unexpected error occurred. Please try again later.",
                ephemeral=True
            )


class GitHubJoinButton(View):
    def __init__(self):
        super().__init__()
        self.add_item(
            Button(
                label="Join GitHub Organization",
                custom_id="github_join_button",
                style=discord.ButtonStyle.primary,
            )
        ) 

    async def on_button_click(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        await interaction.followup.send("You've joined the GitHub organization!", ephemeral=True)
