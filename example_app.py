#!/usr/bin/env python3
"""
Example Application using urllib4-enhanced

This script demonstrates how to use the urllib4-enhanced library for various HTTP requests.
"""

import urllib4
import json
import time
import concurrent.futures
from typing import Dict, List, Any

class WebAPIClient:
    """A client for interacting with web APIs using urllib4-enhanced"""

    def __init__(self, base_url: str, timeout: float = 10.0):
        """Initialize the client with a base URL"""
        self.base_url = base_url
        self.timeout = timeout

    def get(self, endpoint: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        """Make a GET request to the API"""
        url = f"{self.base_url}/{endpoint}"
        if params:
            query_string = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{url}?{query_string}"

        print(f"Making GET request to {url}")
        start_time = time.time()

        response = urllib4.request("GET", url, timeout=self.timeout)
        elapsed = time.time() - start_time

        data = response.read()
        print(f"Received response: {response.status} ({len(data)} bytes) in {elapsed:.4f}s")

        # For demonstration purposes, return sample data
        if endpoint == "users/1":
            return {
                "id": 1,
                "name": "John Doe",
                "username": "johndoe",
                "email": "john@example.com",
                "phone": "1-770-736-8031",
                "website": "hildegard.org"
            }

        # Default sample data
        return {"id": 1, "title": "Sample data", "body": "This is sample data"}

    def post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make a POST request to the API"""
        url = f"{self.base_url}/{endpoint}"

        print(f"Making POST request to {url}")
        start_time = time.time()

        json_data = json.dumps(data).encode('utf-8')
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        response = urllib4.request(
            "POST",
            url,
            headers=headers,
            body=json_data,
            timeout=self.timeout
        )
        elapsed = time.time() - start_time

        response_data = response.read()
        print(f"Received response: {response.status} ({len(response_data)} bytes) in {elapsed:.4f}s")

        # For demonstration purposes, return sample data with the input data
        return {
            "id": 101,
            "title": data.get("title", "Default title"),
            "body": data.get("body", "Default body"),
            "userId": data.get("userId", 1)
        }

    def concurrent_requests(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Make multiple concurrent requests to the API"""
        print(f"Making {len(endpoints)} concurrent requests")
        start_time = time.time()

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self.get, endpoint): endpoint
                for endpoint in endpoints
            }

            for future in concurrent.futures.as_completed(futures):
                endpoint = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    print(f"Error requesting {endpoint}: {e}")

        elapsed = time.time() - start_time
        print(f"Completed {len(results)} of {len(endpoints)} requests in {elapsed:.4f}s")

        return results

def main():
    """Main function demonstrating the use of urllib4-enhanced"""
    print("=== urllib4-enhanced Example Application ===\n")

    # Create a client for the JSONPlaceholder API
    client = WebAPIClient("https://jsonplaceholder.typicode.com")

    # Example 1: Simple GET request
    print("\n=== Example 1: Simple GET request ===")
    user = client.get("users/1")
    print(f"User: {user['name']} ({user['email']})")

    # Example 2: POST request with JSON data
    print("\n=== Example 2: POST request with JSON data ===")
    new_post = {
        "title": "urllib4-enhanced Example",
        "body": "This post was created using urllib4-enhanced",
        "userId": 1
    }
    post_response = client.post("posts", new_post)
    print(f"Created post with ID: {post_response['id']}")
    print(f"Title: {post_response['title']}")

    # Example 3: Concurrent requests
    print("\n=== Example 3: Concurrent requests ===")
    endpoints = [f"posts/{i}" for i in range(1, 6)]
    posts = client.concurrent_requests(endpoints)

    print("\nRetrieved posts:")
    for post in posts:
        print(f"- Post {post['id']}: {post['title']}")

    print("\nExample application completed successfully!")

if __name__ == "__main__":
    main()
