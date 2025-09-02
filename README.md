# note-organizer-16346-16355

## Notes Backend (FastAPI)

- Location: notes_backend
- Run (dev):
  - Create a virtualenv and install requirements.txt
  - Create a .env from notes_backend/.env.example and set JWT_SECRET_KEY in production
  - Start: uvicorn src.api.main:app --reload --host 0.0.0.0 --port 3001

### Auth
- POST /auth/register
- POST /auth/login (OAuth2 password)
- GET /auth/me (Bearer token)

### Notes
- POST /notes
- GET /notes
- GET /notes/{id}
- PUT /notes/{id}
- DELETE /notes/{id}

### Organization
- GET /organization/tags
- GET /organization/folders

### Search
- GET /search?q=term[&tag=...&folder=...]

The current implementation uses in-memory storage for demonstration. Replace with a database in production.