# Babruvahana
Babruvahana is a powerful tool designed for security researchers, web developers, and analysts to find sensitive information embedded in JavaScript files and extract valuable data from HTML content of web pages. 
It is particularly useful for uncovering API keys, tokens, and other confidential information that might be inadvertently exposed.

# Key Features:

   1. JavaScript File Analysis:
        Extract API Keys: Identifies and extracts API keys, tokens, and other sensitive information from JavaScript files.
   2. HTML Content Extraction:
        Extract Images: Finds image URLs embedded in the HTML content of web pages.
        Extract Forms: Retrieves form elements from HTML content, useful for understanding user input structures and potential security vulnerabilities.

# Installation:
To install Babruvahana, clone the repository and navigate to the project directory:
```
git clone https://github.com/parthasec/Babruvahana.git
```
```
cd Babruvahana
```

# Usage
# General Options
To view the available options for Babruvahana, use the -h flag:

```
python babruvahana.py -h
```
![Screenshot 2024-08-28 100256](https://github.com/user-attachments/assets/9633875b-d3cb-4169-a25b-8e7cc1512fc4)

# To Scan JS files
```
python babruvahana.py https://example.com

```
# To Scan images
```
python babruvahana.py https://example.com --images

```
# To Scan Forms
```
python babruvahana.py https://example.com --forms
```


