# BITS Pilani Discord Email Verification Bot

This bot provides email verification for the BITS Pilani Discord server, ensuring that only students with valid BITS Pilani email addresses can access certain channels.

## Features

- Email verification using BITS Pilani student email addresses
- Discord slash command for initiating verification
- Rate limiting to prevent abuse
- Automatic role assignment upon successful verification
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
   ```

3. Install Docker and Docker Compose on your system.

4. Run the bot locally using Docker Compose:
   ```
   docker-compose up --build
   ```

5. The bot should now be running and connected to Discord. You can test it by using the `/verify` command in your Discord server.

## Usage

1. Invite the bot to your Discord server and ensure it has the necessary permissions.
2. Users can start the verification process by using the `/verify` command.
3. The bot will prompt users to enter their BITS Pilani email address.
4. A verification code will be sent to the provided email.
5. Users must enter the verification code to complete the process.
6. Upon successful verification, users will be assigned the "Verified" role.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.