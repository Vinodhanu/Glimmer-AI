"""
Enliven AGENT Core Server (v4.2.0)
NIST SP 800-204 & CNCF Cloud Native Design
"""

import asyncio
import signal
import ssl
from aiohttp import web
from aiohttp_jinja2 import setup as setup_jinja
import jinja2
import uvloop
import prometheus_client
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Configuration
class ServerConfig:
    def __init__(self):
        self.port = int(os.getenv("SERVER_PORT", 443))
        self.ssl_cert = os.getenv("SSL_CERT_PATH", "/etc/ssl/certs/enliven.pem")
        self.ssl_key = os.getenv("SSL_KEY_PATH", "/etc/ssl/private/enliven.key")
        self.ca_cert = os.getenv("CA_CERT_PATH", "/etc/ssl/certs/ca-bundle.pem")
        self.service_discovery_url = os.getenv("CONSUL_URL", "http://consul:8500")
        self.cluster_id = os.getenv("CLUSTER_ID", "default-prod-cluster")
        self.enable_hot_reload = os.getenv("HOT_RELOAD", "false").lower() == "true"

# Middleware
@web.middleware
async def security_middleware(request, handler):
    # OAuth2 JWT Validation
    if request.headers.get("Authorization"):
        try:
            token = request.headers["Authorization"].split("Bearer ")[1]
            request["jwt_claims"] = await validate_jwt(token)
        except Exception as e:
            return web.json_response({"error": "Unauthorized"}, status=401)
    
    # Request ID for distributed tracing
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request["request_id"] = request_id
    
    response = await handler(request)
    response.headers["X-Request-ID"] = request_id
    return response

# Routes
async def health_check(request):
    return web.json_response({
        "status": "healthy",
        "version": "4.2.0",
        "services": await check_dependencies()
    })

async def metrics_handler(request):
    metrics = prometheus_client.generate_latest()
    return web.Response(body=metrics, content_type="text/plain")

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    async for msg in ws:
        if msg.type == web.WSMsgType.TEXT:
            await process_agent_message(ws, msg.data)
        elif msg.type == web.WSMsgType.ERROR:
            log.error(f"WebSocket error: {ws.exception()}")
    
    return ws

# Core Server
class EnlivenServer:
    def __init__(self, config):
        self.app = web.Application(middlewares=[security_middleware])
        self.config = config
        self.runner = None
        self.ssl_context = None
        
        # Setup components
        self._configure_ssl()
        self._configure_routes()
        self._configure_templates()
        self._configure_signals()
        
    def _configure_ssl(self):
        context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.config.ssl_cert, self.config.ssl_key)
        context.load_verify_locations(self.config.ca_cert)
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")
        self.ssl_context = context

    def _configure_routes(self):
        self.app.router.add_get("/health", health_check)
        self.app.router.add_get("/metrics", metrics_handler)
        self.app.router.add_get("/ws", websocket_handler)
        self.app.router.add_post("/api/v1/agents", create_agent)
        self.app.router.add_put("/api/v1/agents/{agent_id}", update_agent)
        
    def _configure_templates(self):
        setup_jinja(self.app, loader=jinja2.FileSystemLoader("/opt/enliven/templates"))
        
    def _configure_signals(self):
        self.app.on_startup.append(self.on_startup)
        self.app.on_shutdown.append(self.on_shutdown)
        self.app.on_cleanup.append(self.on_cleanup)
        
    async def on_startup(self, app):
        await self.register_service()
        await self.initialize_cluster()
        
    async def on_shutdown(self, app):
        await self.deregister_service()
        await self.close_connections()
        
    async def on_cleanup(self, app):
        await self.cleanup_resources()

    async def run(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(
            self.runner, 
            port=self.config.port, 
            ssl_context=self.ssl_context
        )
        await site.start()
        
        if self.config.enable_hot_reload:
            asyncio.create_task(self.watch_config_changes())

    # Service Discovery
    async def register_service(self):
        async with aiohttp.ClientSession() as session:
            await session.put(
                f"{self.config.service_discovery_url}/v1/agent/service/register",
                json={
                    "ID": f"enliven-{socket.gethostname()}",
                    "Name": "enliven-agent",
                    "Address": await get_host_ip(),
                    "Port": self.config.port,
                    "Check": {
                        "HTTP": f"https://localhost:{self.config.port}/health",
                        "Interval": "10s"
                    }
                }
            )

    # Cluster Management
    async def initialize_cluster(self):
        self.cluster_state = await fetch_cluster_state(self.config.cluster_id)
        self.task_queue = create_priority_queue()
        self.load_balancer = create_load_balancer(self.cluster_state)

# Utilities
async def get_host_ip():
    # Kubernetes-aware IP detection
    if os.path.exists("/var/run/secrets/kubernetes.io"):
        return os.getenv("POD_IP", "127.0.0.1")
    return socket.gethostbyname(socket.gethostname())

def create_event_loop():
    uvloop.install()
    loop = asyncio.get_event_loop()
    loop.set_debug(os.getenv("DEBUG", "false").lower() == "true")
    return loop

# Signal Handlers
def handle_signal(signum):
    async def shutdown():
        await server.runner.cleanup()
        loop.stop()
    asyncio.create_task(shutdown())

# Main Execution
if __name__ == "__main__":
    config = ServerConfig()
    validate_config(config)
    
    loop = create_event_loop()
    server = EnlivenServer(config)
    
    # Signal handling
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: handle_signal(sig))
    
    try:
        loop.run_until_complete(server.run())
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
