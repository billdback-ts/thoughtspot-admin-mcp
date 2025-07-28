# thoughtspot-admin-mcp

A Model Context Protocol (MCP) server that provides ThoughtSpot administrative capabilities through Claude Desktop. This server allows you to search and analyze metadata from your ThoughtSpot instance, including liveboards, answers, logical tables, connections, tags, and user groups.

## Features

- **Metadata Search**: Search across all ThoughtSpot metadata types with filtering capabilities
- **Advanced Filtering**: Filter by metadata type, author, tags, and other criteria
- **Pagination Support**: Handle large result sets with offset and limit parameters
- **Usage Analytics**: Access view counts and last access timestamps
- **Content Governance**: Analyze content distribution and tagging strategies

## Available Tools

### `search-metadata`

Searches ThoughtSpot metadata objects with flexible filtering options.

**Parameters:**
- `types` (optional): Array of metadata types to search for
  - Valid types: `LIVEBOARD`, `ANSWER`, `LOGICAL_TABLE`, `CONNECTION`, `TAG`, `USER_GROUP`
  - Leave empty to search all types
- `authors` (optional): Array of author names to filter by
- `tags` (optional): Array of tag names to filter by
- `offset` (optional): Record offset for pagination (default: 0)
- `limit` (optional): Maximum number of records to return (default: 100, max: 1000)

**Returns:**
- Metadata ID and object ID
- Object name and type
- Author information
- Creation and modification timestamps
- Associated tags
- Usage statistics (views, last access)
- Object descriptions

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd thoughtspot-admin-mcp
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration for Claude Desktop

### 1. Create MCP Configuration File

Create a configuration file for Claude Desktop. The location depends on your operating system:

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```
~/.config/Claude/claude_desktop_config.json
```

### 2. Add MCP Server Configuration

Add the following configuration to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "thoughtspot-admin": {
      "command": "python",
      "args": [
        "/path/to/thoughtspot-admin-mcp/thoughtspot_admin_mcp.py",
        "--tsurl", "https://your-thoughtspot-server.cloud",
        "--username", "your-username",
        "--token", "your-api-token"
      ]
    }
  }
}
```

NOTE that you will likely need to specify the full path to your Python environment that has the requirements installed.  

**Replace the following values:**
- `/path/to/thoughtspot-admin-mcp/`: Full path to this repository
- `https://your-thoughtspot-server.cloud`: Your ThoughtSpot server URL
- `your-username`: Your ThoughtSpot username
- `your-api-token`: Your ThoughtSpot API token

### 3. Generate API Token

To get your ThoughtSpot API token:

1. Log into your ThoughtSpot instance
2. Go to **Developer** → **REST Playground v2.0** → **Authentication** → **Get Full Access Token**
3. Create a new token using your username, password, and validity time.  A longer time is probably wise so it doesn't expire.
4. Copy the token value for use in the configuration

### 4. Restart Claude Desktop

After updating the configuration file, restart Claude Desktop for the changes to take effect.

## Usage Examples

### Find All Liveboards
```
Search for all liveboards in the system
```

### Find Content by Specific Author
```
Find all content created by john.doe
```

### Find Objects with Specific Tags
```
Find all objects tagged with "Finance" or "Marketing"
```

### Analyze Usage Patterns
```
Find liveboards with low usage (less than 10 views)
```

### Content Audit
```
Find all objects that haven't been accessed in the last 30 days
```

## Development

### Testing the Connection

You can test the connection to your ThoughtSpot instance:

```bash
python thoughtspot_admin_mcp.py --tsurl https://your-server.cloud --username your-username --token your-token --test
```

This will fetch all liveboards and answers and output them as JSON.

### Running the Server Directly

For development or debugging:

```bash
python thoughtspot_admin_mcp.py --tsurl https://your-server.cloud --username your-username --token your-token
```

## Requirements

- Python 3.10 or higher
- ThoughtSpot REST API v1 library
- MCP library
- Valid ThoughtSpot instance with API access

## Security Notes

- Store your API token securely
- Use environment variables for sensitive configuration in production
- Regularly rotate your API tokens
- Ensure your ThoughtSpot instance has proper security configurations

## Troubleshooting

### Common Issues

1. **Connection Failed**: Verify your ThoughtSpot URL, username, and token
2. **Permission Denied**: Ensure your API token has appropriate permissions
3. **Invalid URL**: Make sure the URL starts with `http://` or `https://`
4. **Python Path**: Ensure the correct Python interpreter is specified in the MCP configuration

### Debug Logging

The server creates debug logs in `mcp_debug.log` (or `/tmp/mcp_debug.log` if the current directory is not writable). Check this file for detailed error information.

## License

MIT License
