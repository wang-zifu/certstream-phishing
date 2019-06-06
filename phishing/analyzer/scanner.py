from urllib.request import urlopen, Request, HTTPError, URLError

def make_request(request):
    response = None
    open_dir = None
    try:
        resp = urlopen(request, timeout=10)
    except HTTPError as e:
        response = e.code
    except Exception as e:
        pass
    else:
        response = 200
        body = ""
        
        try:
            body = resp.read().decode('utf-8')
        except:
            pass

        if "Index of" in body:
            open_dir = True
        else:
            open_dir = False
    
    return response, open_dir


def connect_to_domain(domain):
    response_http = None
    response_https = None
    open_dir_http = None
    open_dir_https = None
    response_http, open_dir_http = make_request(Request("http://" + domain))
    response_https, open_dir_https = make_request(Request("https://" + domain))

    if open_dir_http:
        return response_http, response_https, open_dir_http

    return response_http, response_https, open_dir_https