"""Uploads the browser extension to the stores and submits it for review.

    python3 -I extension_stores.py chrome|firefox|edge <folder> <version>

release.yml runs it once the app's release is out. <folder> holds the zips
`pnpm extension:package` makes for <version> and, for Firefox, the source
archive. Each store's credentials come from the environment (secrets of the
`extension-stores` environment); a store without them is skipped with a
notice, so adding its secrets is what turns a store on. Only the standard
library is used: nothing is installed on the runner that holds them.

- Chrome Web Store, API v2: CWS_CLIENT_ID, CWS_CLIENT_SECRET and
  CWS_REFRESH_TOKEN (an OAuth client with the Chrome Web Store API, and a
  refresh token of the publisher's account for it) and CWS_PUBLISHER_ID.
  The new version goes live as soon as review approves it.
- addons.mozilla.org, API v5: AMO_JWT_ISSUER and AMO_JWT_SECRET (an API key
  of the add-on's account). The version takes the source archive along: the
  scripts are bundled, and reviewers rebuild them from it.
- Microsoft Edge Add-ons, API v1.1: EDGE_CLIENT_ID, EDGE_API_KEY and
  EDGE_PRODUCT_ID. Partner Center shows when the API key expires.

Only the package changes; the listings stay as the stores have them. A store
refuses a version it has already, so after a failure past the upload, finish
that store by hand.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

# `CHROMIUM_EXTENSION_IDS` in src-tauri/src/browser/mod.rs.
CHROME_ITEM = "lkmgdcanagjeajepncgokapkbihahddb"
# `browser_specific_settings.gecko.id` in extension/manifest.json.
FIREFOX_ID = "autofill@sshkeymanager.dev"

GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
CHROME_API = "https://chromewebstore.googleapis.com"
AMO_API = "https://addons.mozilla.org/api/v5"
EDGE_API = "https://api.addons.microsoftedge.microsoft.com/v1"

# How often, and how long, a store's processing is waited for.
POLL_EVERY = 5
POLL_FOR = 15 * 60

AMO_NOTES = (
    "The scripts are bundled from TypeScript with Vite; the attached source "
    "is the whole repository at the release tag. To rebuild them: Node 22, "
    "then `corepack enable`, `pnpm install --frozen-lockfile` and "
    "`pnpm extension:package` in the repository's root. The add-on is in "
    "extension/dist/firefox, and extension/README.md says more. It talks to "
    "the SSH Key Manager desktop app through native messaging."
)


class Failed(Exception):
    pass


def request(method, url, body=None, headers=None):
    """Sends a request and returns (status, headers, body); fails on an HTTP error."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as error:
        text = error.read().decode("utf-8", "replace")[:4000]
        raise Failed(f"{method} {url}: HTTP {error.code}: {text}") from None


def parsed(raw):
    return json.loads(raw) if raw else {}


def credentials(store, *names):
    """The values of `names`, or None (and a notice) if any is unset."""
    values = [os.environ.get(name, "") for name in names]
    missing = [name for name, value in zip(names, values) if not value]
    if missing:
        print(f"::notice::{store}: skipped, without {', '.join(missing)}")
        return None
    return values


def package(folder, name):
    path = os.path.join(folder, name)
    if os.path.islink(path) or not os.path.isfile(path):
        raise Failed(f"no {name} in {folder}")
    with open(path, "rb") as file:
        return file.read()


def wait(what, check):
    """Calls `check` until it returns something other than None."""
    deadline = time.monotonic() + POLL_FOR
    while True:
        result = check()
        if result is not None:
            return result
        if time.monotonic() > deadline:
            raise Failed(f"{what}: not done after {POLL_FOR} seconds")
        time.sleep(POLL_EVERY)


def multipart(fields):
    """A multipart/form-data body of (name, value) or (name, (filename, bytes)) pairs."""
    boundary = uuid.uuid4().hex
    parts = []
    for name, value in fields:
        if isinstance(value, tuple):
            filename, data = value
            head = (
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                "Content-Type: application/zip\r\n"
            )
        else:
            head = f'Content-Disposition: form-data; name="{name}"\r\n'
            data = value.encode()
        parts.append(f"--{boundary}\r\n{head}\r\n".encode() + data + b"\r\n")
    body = b"".join(parts) + f"--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def chrome(folder, version):
    found = credentials(
        "Chrome Web Store",
        "CWS_CLIENT_ID",
        "CWS_CLIENT_SECRET",
        "CWS_REFRESH_TOKEN",
        "CWS_PUBLISHER_ID",
    )
    if not found:
        return
    client_id, client_secret, refresh_token, publisher = found
    data = package(folder, f"ssh-key-manager-chromium-{version}.zip")

    form = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
    ).encode()
    _, _, raw = request(
        "POST", GOOGLE_TOKEN, form, {"Content-Type": "application/x-www-form-urlencoded"}
    )
    auth = {"Authorization": f"Bearer {parsed(raw)['access_token']}"}
    item = f"publishers/{urllib.parse.quote(publisher, safe='')}/items/{CHROME_ITEM}"

    _, _, raw = request(
        "POST",
        f"{CHROME_API}/upload/v2/{item}:upload",
        data,
        {**auth, "Content-Type": "application/zip"},
    )
    upload = parsed(raw)
    state = upload.get("uploadState")
    if state == "IN_PROGRESS":

        def uploaded():
            _, _, raw = request("GET", f"{CHROME_API}/v2/{item}:fetchStatus", headers=auth)
            last = parsed(raw).get("lastAsyncUploadState")
            return None if last in (None, "IN_PROGRESS") else last

        state = wait("Chrome Web Store upload", uploaded)
    if state != "SUCCEEDED":
        raise Failed(f"Chrome Web Store upload: {state}: {json.dumps(upload)}")
    print(f"Chrome Web Store: uploaded {version}")

    try:
        _, _, raw = request(
            "POST",
            f"{CHROME_API}/v2/{item}:publish",
            json.dumps({"publishType": "DEFAULT_PUBLISH"}).encode(),
            {**auth, "Content-Type": "application/json"},
        )
    except Failed as failure:
        if "INVALID_ITEM_METADATA" in str(failure):
            print(
                f"::error::Chrome Web Store: {version} is uploaded but not submitted. The "
                "dashboard is missing something this version needs, most often the "
                "justification of a permission the manifest added (extension/store/en.md, "
                "Privacy). Fill it in on the dashboard, then choose Submit for review there."
            )
        raise
    result = parsed(raw)
    if result.get("warningInfo"):
        print(f"::warning::Chrome Web Store: {json.dumps(result['warningInfo'])}")
    print(f"Chrome Web Store: submitted for review ({result.get('state', 'no state given')})")


def amo_token(issuer, secret):
    """A JWT for the AMO API, good for five minutes."""

    def encode(value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    now = int(time.time())
    claims = {"iss": issuer, "jti": uuid.uuid4().hex, "iat": now, "exp": now + 300}
    signing = encode({"alg": "HS256", "typ": "JWT"}) + b"." + encode(claims)
    signature = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
    return (signing + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()


def firefox(folder, version):
    found = credentials("addons.mozilla.org", "AMO_JWT_ISSUER", "AMO_JWT_SECRET")
    if not found:
        return
    issuer, secret = found
    data = package(folder, f"ssh-key-manager-firefox-{version}.zip")
    source_name = f"ssh-key-manager-source-{version}.zip"
    source = package(folder, source_name)

    def auth():
        return {"Authorization": f"JWT {amo_token(issuer, secret)}"}

    body, kind = multipart(
        [("upload", (f"ssh-key-manager-firefox-{version}.zip", data)), ("channel", "listed")]
    )
    _, _, raw = request(
        "POST", f"{AMO_API}/addons/upload/", body, {**auth(), "Content-Type": kind}
    )
    upload = parsed(raw)["uuid"]

    def validated():
        _, _, raw = request("GET", f"{AMO_API}/addons/upload/{upload}/", headers=auth())
        detail = parsed(raw)
        return detail if detail.get("processed") else None

    detail = wait("addons.mozilla.org validation", validated)
    if not detail.get("valid"):
        messages = detail.get("validation", {}).get("messages", [])
        for message in messages:
            if message.get("type") == "error":
                print(f"::error::addons.mozilla.org: {message.get('message')}")
        raise Failed("addons.mozilla.org: the package didn't pass validation")
    print(f"addons.mozilla.org: uploaded {version}")

    addon = urllib.parse.quote(FIREFOX_ID, safe="")
    body, kind = multipart(
        [("upload", upload), ("approval_notes", AMO_NOTES), ("source", (source_name, source))]
    )
    _, _, raw = request(
        "POST",
        f"{AMO_API}/addons/addon/{addon}/versions/",
        body,
        {**auth(), "Content-Type": kind},
    )
    print(f"addons.mozilla.org: version {parsed(raw).get('version', version)} submitted")


def edge(folder, version):
    found = credentials("Edge Add-ons", "EDGE_CLIENT_ID", "EDGE_API_KEY", "EDGE_PRODUCT_ID")
    if not found:
        return
    client_id, api_key, product = found
    data = package(folder, f"ssh-key-manager-chromium-{version}.zip")
    auth = {"Authorization": f"ApiKey {api_key}", "X-ClientID": client_id}
    base = f"{EDGE_API}/products/{urllib.parse.quote(product, safe='')}/submissions"

    def operation(headers):
        location = headers.get("Location", "")
        found = location.rstrip("/").rsplit("/", 1)[-1]
        if not found:
            raise Failed("Edge Add-ons: no operation in the answer's Location header")
        return urllib.parse.quote(found, safe="")

    def finished(url, what):
        def check():
            _, _, raw = request("GET", url, headers=auth)
            status = parsed(raw)
            return None if status.get("status") in (None, "InProgress") else status

        status = wait(what, check)
        if status.get("status") != "Succeeded":
            raise Failed(f"{what}: {json.dumps(status)}")

    _, headers, _ = request(
        "POST", f"{base}/draft/package", data, {**auth, "Content-Type": "application/zip"}
    )
    finished(f"{base}/draft/package/operations/{operation(headers)}", "Edge Add-ons upload")
    print(f"Edge Add-ons: uploaded {version}")

    notes = json.dumps({"notes": f"SSH Key Manager {version}, released with the desktop app."})
    _, headers, _ = request(
        "POST", base, notes.encode(), {**auth, "Content-Type": "application/json"}
    )
    finished(f"{base}/operations/{operation(headers)}", "Edge Add-ons submission")
    print("Edge Add-ons: submitted for review")


STORES = {"chrome": chrome, "firefox": firefox, "edge": edge}


def main(argv):
    if len(argv) != 4 or argv[1] not in STORES:
        sys.exit(f"usage: {argv[0]} {'|'.join(STORES)} <folder> <version>")
    try:
        STORES[argv[1]](argv[2], argv[3])
    except Failed as failure:
        print(f"::error::{failure}")
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
