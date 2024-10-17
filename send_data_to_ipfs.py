
import requests
import hashlib
import os
import json

def send_file_to_ipfs_sync(file_path, ipfs_api_url="http://localhost:5001"):
    """Sends a file to IPFS synchronously using requests."""
    try:
        response = requests.post(f"{ipfs_api_url}/api/v0/add", files={"file": open(file_path, "rb")})
        print(response.status_code)
        #print(response.text)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()["Hash"]
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None
    except (KeyError, json.JSONDecodeError) as e:
        print(f"Error decoding JSON response: {e}")
        return None

def get_file_from_ipfs_sync(ipfs_hash, ipfs_api_url="http://localhost:5001"):
    """Retrieves a file from IPFS synchronously using requests."""
    try:
        response = requests.post(f"{ipfs_api_url}/api/v0/cat/{ipfs_hash}")
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        print(response.status_code)
        print(response.text)
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving file from IPFS: {e}")
        return None

def main():
    # Отправка файла в ipfs
    file_path = "nft_certificate.png"  # Имя файла котороый хоти отправитьь
    try:
        ipfs_hash = send_file_to_ipfs_sync(file_path)   # Use sync
        if ipfs_hash:
            print(f"File uploaded to IPFS with hash: {ipfs_hash}")
    except Exception as e:
        print(f"An error occurred: {e}")

    # Получение файла из ipfs
    print(get_file_from_ipfs_sync(ipfs_hash))

if __name__ == "__main__":
    main()

