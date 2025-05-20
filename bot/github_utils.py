import os
import logging
import httpx
from dotenv import load_dotenv
from upstash_redis.asyncio import Redis
from upstash_ratelimit.asyncio import Ratelimit, FixedWindow
import time

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_ORG_NAME = os.getenv("GITHUB_ORG_NAME", "bits-bsc-cs")
UPSTASH_REDIS_REST_URL = os.getenv("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.getenv("UPSTASH_REDIS_REST_TOKEN")

# Upstash Redis setup
redis_client = Redis(url=UPSTASH_REDIS_REST_URL, token=UPSTASH_REDIS_REST_TOKEN)

# Upstash Ratelimit setup for GitHub invitations
github_ratelimit = Ratelimit(
    redis=redis_client,
    limiter=FixedWindow(max_requests=3, window=86400),
    prefix="github_ratelimit",
)

async def check_github_rate_limit(user_id: str) -> bool:
    """
    Check if user has exceeded GitHub invitation rate limit
    
    Args:
        user_id (str): Discord user ID
        
    Returns:
        bool: True if allowed, False if rate limited
    """
    identifier = f"user:{user_id}"
    result = await github_ratelimit.limit(identifier)
    
    if not result.allowed:
        logger.info(f"Rate limit exceeded for user {user_id} - GitHub invitations")
        remaining_time = result.reset_in
        remaining_hours = int(remaining_time / 3600)
        remaining_minutes = int((remaining_time % 3600) / 60)
        logger.debug(f"Rate limit will reset in {remaining_hours}h {remaining_minutes}m")
        
    return result.allowed

async def invite_to_github(username: str) -> dict:
    """
    Invite a user to the GitHub organization.
    
    Args:
        username (str): GitHub username to invite
        
    Returns:
        dict: Response with success/failure status and message
        
    Raises:
        ValueError: If the GitHub username is invalid
    """
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN not configured")
        return {"success": False, "message": "GitHub integration not configured"}
        
    logger.info(f"Attempting to invite GitHub user: {username}")
    
    # First validate the GitHub username exists
    async with httpx.AsyncClient() as client:
        # Check if username exists
        logger.debug(f"Checking if GitHub user {username} exists")
        user_response = await client.get(
            f"https://api.github.com/users/{username}",
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
        )
        
        if user_response.status_code != 200:
            logger.error(f"GitHub user validation failed: {user_response.status_code} - {user_response.text}")
            return {"success": False, "message": "GitHub username not found. Please check and try again."}
        
        # Send invitation
        logger.debug(f"Sending invitation to GitHub user {username}")
        invite_url = f"https://api.github.com/orgs/{GITHUB_ORG_NAME}/invitations"
        invite_data = {
            "invitee_id": user_response.json()["id"],
            "role": "direct_member"
        }
        
        invite_response = await client.post(
            invite_url,
            json=invite_data,
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
        )
        
        # Handle common API responses
        if invite_response.status_code == 201:
            logger.info(f"Successfully invited {username} to {GITHUB_ORG_NAME}")
            return {"success": True, "message": f"Successfully invited to {GITHUB_ORG_NAME} GitHub organization!"}
        elif invite_response.status_code == 422:
            error_data = invite_response.json()
            if "errors" in error_data and any(e.get("message") == "User is already a member" for e in error_data["errors"]):
                logger.info(f"User {username} is already a member of {GITHUB_ORG_NAME}")
                return {"success": False, "message": f"You are already a member of {GITHUB_ORG_NAME} GitHub organization."}
            elif "errors" in error_data and any(e.get("message") == "User has already been invited" for e in error_data["errors"]):
                logger.info(f"User {username} has already been invited to {GITHUB_ORG_NAME}")
                return {"success": False, "message": f"You have already been invited to {GITHUB_ORG_NAME} GitHub organization. Check your email."}
        elif invite_response.status_code == 403:
            logger.error(f"Permission denied: {invite_response.text}")
            return {"success": False, "message": "GitHub token doesn't have permission to invite users."}
        elif invite_response.status_code == 429:
            logger.error(f"GitHub API rate limit exceeded: {invite_response.text}")
            return {"success": False, "message": "GitHub API rate limit exceeded. Please try again later."}
        
        # Other error responses
        logger.error(f"GitHub API error: {invite_response.status_code} - {invite_response.text}")
        return {"success": False, "message": f"Failed to send GitHub invitation. Error code: {invite_response.status_code}"} 