This script takes passwords entered as CLI arguements, hashes them, and sends a request to the [haveibeenpwned API](https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange) to check if the password is listed in the response. For increased security, the API uses the [k-anonymity model](https://en.wikipedia.org/wiki/K-anonymity) to send the request, so only the first 5 hashed characters are sent in the request instead of the whole hashed password. The script will then check the API response for a match of the rest of the hashed characters that were not sent, and print the number of leaks for each given password to the terminal.