# BITS Pilani Discord Bot

This bot provides email verification for the BITS Pilani Discord server, ensuring that only students with valid BITS Pilani email addresses can access certain channels. It also allows verified users to join the GitHub organization.

## Features

- Email verification using BITS Pilani student email addresses
- Discord slash command for initiating verification
- Rate limiting to prevent abuse
- Automatic role assignment upon successful verification
- GitHub organization invitation for verified users
- Docker support for easy deployment

## Local Development Setup

1. Clone the repository:
   ```
   git clone https://github.com/bits-bsc-cs/discord-bot.git
   cd discord-bot
   ```

2. Create a `.env` file in the root directory with the following variables:
   ```
   DISCORD_TOKEN=your_discord_bot_token
   RESEND_API_KEY=your_resend_api_key
   GITHUB_TOKEN=your_github_personal_access_token_with_admin_org_permission
   GITHUB_ORG_NAME=bits-bsc-cs
   ```

3. Install Docker and Docker Compose on your system.

4. Run the bot locally using Docker Compose:
   ```
   docker-compose up --build
   ```

5. The bot should now be running and connected to Discord. You can test it by using the `/verify` and `/github-join` commands in your Discord server.

## Usage

### Email Verification
1. Invite the bot to your Discord server and ensure it has the necessary permissions.
2. Users can start the verification process by using the `/verify` command.
3. The bot will prompt users to enter their BITS Pilani email address.
4. A verification code will be sent to the provided email.
5. Users must enter the verification code to complete the process.
6. Upon successful verification, users will be assigned the "Verified" role.

### GitHub Organization Invitation
1. Verified users can request to join the GitHub organization by using the `/github-join` command.
2. The bot will prompt users to enter their GitHub username.
3. If the username is valid, an invitation will be sent to join the organization.
4. Users can check their GitHub notifications or email to accept the invitation.
5. Rate limiting is applied (3 requests per 24 hours) to prevent abuse.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.