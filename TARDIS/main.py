# code to run the api/api/py fastapi server
import uvicorn
from api import app

if __name__ == "__main__":
    uvicorn.run(app=app, host="0.0.0.0", port=8000)