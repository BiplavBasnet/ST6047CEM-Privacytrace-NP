"""Route introspection compatible with FastAPI's lazy included routers."""


def registered_routes(app):
    for route in app.routes:
        original_router = getattr(route, "original_router", None)
        if original_router is not None:
            yield from original_router.routes
        else:
            yield route
