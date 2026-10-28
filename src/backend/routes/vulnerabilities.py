from fastapi import APIRouter, Path, Request

router = APIRouter(prefix="/api", tags=["vulnerabilities"])


@router.get("/vulnerabilities")
def get_vulnerabilities(request: Request):
    return request.app.state.database.get_all_vulnerabilities()


@router.get("/recommendations/{port}")
def get_recommendations(request: Request, port: int = Path(ge=1, le=65535)):
    return request.app.state.database.get_recommendations(port)
