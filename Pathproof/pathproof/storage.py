from collections.abc import Iterator, Callable
from contextlib import contextmanager
from secrets import token_hex
from urllib.parse import urlsplit

CANARY = b"PathProof planted classroom object v1\n"


def guard(url: str, owned_port: int) -> None:
    parts = urlsplit(url)
    if (type(owned_port) is not int or not 1 <= owned_port <= 65535 or parts.scheme != "http"
            or parts.netloc != f"127.0.0.1:{owned_port}" or parts.fragment):
        raise ValueError("Refused destination outside the owned loopback listener.")


@contextmanager
def storage(backend: str) -> Iterator[Callable[[], bytes]]:
    if backend == "memory":
        yield lambda: CANARY
        return
    if backend != "moto":
        raise ValueError("Unknown storage backend.")
    import boto3
    from botocore.config import Config
    from moto.server import ThreadedMotoServer

    server = ThreadedMotoServer(ip_address="127.0.0.1", port=0, verbose=False)
    server.start()
    try:
        host, port = server.get_host_and_port()
        endpoint = f"http://{host}:{port}"
        guard(endpoint, port)
        config = Config(proxies={}, retries={"total_max_attempts": 1}, s3={"addressing_style": "path"})
        client = boto3.client("s3", region_name="us-east-1", endpoint_url=endpoint,
                              aws_access_key_id="classroom", aws_secret_access_key="classroom", config=config)
        def before_send(request, **kwargs) -> None:
            guard(request.url, port)
        client.meta.events.register("before-send.s3", before_send)
        bucket = "pathproof-" + token_hex(8)
        try:
            client.create_bucket(Bucket=bucket)
            client.put_object(Bucket=bucket, Key="canary.txt", Body=CANARY)
            def fetch() -> bytes:
                stream = client.get_object(Bucket=bucket, Key="canary.txt")["Body"]
                try:
                    return stream.read(len(CANARY) + 1)
                finally:
                    stream.close()
            yield fetch
        finally:
            client.close()
    finally:
        server.stop()
