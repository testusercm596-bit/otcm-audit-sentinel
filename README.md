# OTCM Audit Sentinel 🛡️

AI-Powered Security Analysis Tool for OpenText Content Manager

## Overview

OTCM Audit Sentinel is a Python-based AI security tool that uses two intelligent agents to analyze and protect your OpenText Content Manager environment:

- **Sentinel Agent**: Analyzes audit logs for anomalies and security threats
- **Hallucinator Agent**: Performs AI-powered security testing to identify vulnerabilities

## Architecture

This project follows Clean Architecture principles with the following structure:

```
otcm-audit-sentinel/
├── src/
│   ├── domain/           # Core business entities and models
│   ├── infrastructure/   # Database and external API clients
│   ├── application/      # Sentinel and Hallucinator agents
│   └── interface/        # Streamlit UI and API endpoints
├── config/               # Configuration and environment variables
├── tests/                # Unit and integration tests
└── requirements.txt      # Project dependencies
```

## Features

- 🔍 **Intelligent Audit Analysis**: AI-powered analysis of audit logs to detect anomalies
- 🎯 **Proactive Security Testing**: Creative vulnerability discovery using AI
- 📊 **Interactive Dashboard**: Real-time monitoring via Streamlit interface
- 🔌 **REST API**: Programmatic access to all features
- 🗄️ **Vector Database**: pgvector integration for semantic search
- 📈 **Comprehensive Reporting**: Detailed security findings and recommendations

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd otcm-audit-sentinel
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
cp .env.template .env
# Edit .env with your actual configuration
```

5. Start the PostgreSQL database with pgvector:
```bash
docker-compose up -d
```

## Configuration

Edit the `.env` file with your configuration:

```env
# Database
POSTGRES_USER=otcm_user
POSTGRES_PASSWORD=your_secure_password_here
POSTGRES_DB=otcm_audit_sentinel
DATABASE_URL=postgresql://otcm_user:your_secure_password_here@localhost:5432/otcm_audit_sentinel

# Content Manager
CM_BASE_URL=https://your-content-manager.example.com
CM_USERNAME=your_username
CM_PASSWORD=your_password
CM_DOMAIN=YOUR_DOMAIN

# OpenAI
OPENAI_API_KEY=your_openai_api_key_here
```

## Docker Setup

The project includes a Docker Compose configuration for PostgreSQL with pgvector support:

```bash
# Start the database
docker-compose up -d

# Check database status
docker-compose ps

# View logs
docker-compose logs -f db

# Stop the database
docker-compose down

# Stop and remove volumes (WARNING: deletes all data)
docker-compose down -v
```

## Database Setup

After starting the PostgreSQL container, initialize the database:

```bash
# Initialize database (enables pgvector extension and creates tables)
python scripts/init_db.py
```

This will:
- Enable the pgvector extension
- Create all required tables (audit_logs, security_findings, etc.)
- Set up indexes for efficient querying

## Usage

### Running the Main Application

The main application continuously monitors Content Manager audit logs:

```bash
# Run with default settings (checks every 60 seconds)
python main.py

# Or use interactive mode
python run_interactive.py
```

**What it does:**
1. Fetches new audit logs from Content Manager
2. Stores logs in PostgreSQL with vector embeddings
3. Runs Sentinel detection on each event
4. For alerts: generates Hallucinator defense
5. Makes final decision (dismiss or escalate)
6. Stores results in database

### Interactive Mode

```bash
python run_interactive.py
```

Options:
- Run single check iteration
- Run continuous monitoring
- View recent alerts
- Exit

### Running the Streamlit UI

**New Interactive Dashboard:**
```bash
streamlit run src/interface/app.py
```

This shows:
- **Live Feed** (left): Real-time logs and alerts
- **Security Debate** (right): Sentinel vs Hallucinator analysis
- **Decision Buttons**: Ignore or Investigate alerts

**Original Dashboard:**
```bash
streamlit run src/interface/streamlit_app.py
```

### Running the API Server

```bash
python src/interface/api.py
```

Or with uvicorn:
```bash
uvicorn src.interface.api:app --reload
```

### Using the Sentinel Agent

```python
from src.application.sentinel import SentinelAgent, UserProfile, SecurityAlert

# Define security rules
rules = [
    {
        'name': 'Excessive Deletes',
        'condition': 'event_type',
        'operator': '==',
        'value': 'DELETE',
        'threshold': 5,
        'risk_score': 0.8,
        'description': 'Too many delete operations'
    }
]

# Create user profiles with behavioral baselines
user_profiles = {
    "john.doe": UserProfile(
        user_id="john.doe",
        baseline_embedding=[0.5] * 1536  # Normal behavior embedding
    )
}

# Initialize Sentinel Agent
sentinel = SentinelAgent(rules=rules, user_profiles=user_profiles)

# Evaluate an event
event = {
    'user_id': 'john.doe',
    'event_type': 'DELETE',
    'timestamp': '2026-02-05T10:00:00',
    'embedding': [0.6] * 1536
}

alert = sentinel.evaluate_event(event)
if alert.is_alert:
    print(f"⚠️  Alert: {alert.reason}")
    print(f"Risk Score: {alert.risk_score}")
```

### Using the Hallucinator Agent

```python
from src.application.hallucinator import HallucinatorAgent

# Initialize Hallucinator Agent
hallucinator = HallucinatorAgent(model="gpt-4", temperature=0.7)

# Generate defense for an alert
alert = {
    'is_alert': True,
    'risk_score': 0.8,
    'reason': 'Excessive delete operations',
    'event': {
        'user_id': 'john.doe',
        'event_type': 'DELETE',
        'timestamp': '2026-02-05T16:30:00'
    }
}

user_history = [
    {'event_type': 'READ', 'timestamp': '2026-02-05T09:00:00'},
    {'event_type': 'WRITE', 'timestamp': '2026-02-05T10:30:00'}
]

# Generate benign justification
defense = hallucinator.generate_defense(alert, user_history)

print(f"Defense Confidence: {defense.confidence}")
print(f"Justification: {defense.justification}")

# Decide if alert should be dismissed
if hallucinator.should_dismiss_alert(defense, confidence_threshold=0.7):
    print("✅ Alert dismissed as false positive")
else:
    print("🚨 Alert requires investigation")
```

### Combined Workflow: Detection + Defense

```python
from src.application.sentinel import SentinelAgent, UserProfile
from src.application.hallucinator import HallucinatorAgent

# Setup both agents
sentinel = SentinelAgent(rules=rules, user_profiles=user_profiles)
hallucinator = HallucinatorAgent()

# 1. Detect with Sentinel
alert = sentinel.evaluate_event(event)

if alert.is_alert:
    # 2. Generate defense with Hallucinator
    defense = hallucinator.generate_defense(
        {
            'is_alert': True,
            'risk_score': alert.risk_score,
            'reason': alert.reason,
            'event': event
        },
        user_history
    )
    
    # 3. Make decision
    if defense.confidence >= 0.7:
        print("False positive - dismissing alert")
    else:
        print("Genuine threat - escalating for investigation")
```

### Using the Content Manager Client

```python
from src.infrastructure.cm_client import ContentManagerClient
from datetime import datetime, timedelta

# Create client
client = ContentManagerClient(
    base_url="https://your-cm.example.com",
    username="your_username",
    password="your_password",
    domain="YOUR_DOMAIN"
)

# Fetch recent logs
last_checked = datetime.utcnow() - timedelta(hours=1)
logs = client.fetch_recent_logs(last_checked)

# Fetch logs with embeddings
logs_with_embeddings = client.fetch_and_embed_logs(last_checked)

# Convert text to embedding
embedding = client.convert_to_embedding("User performed READ on Document")
```

### Using the Agents Programmatically

```python
from src.application.sentinel_agent import SentinelAgent
from src.application.hallucinator_agent import HallucinatorAgent

# Initialize agents
sentinel = SentinelAgent(openai_api_key="your_key")
hallucinator = HallucinatorAgent(openai_api_key="your_key")

# Analyze audit logs
findings = sentinel.analyze_audit_logs(audit_records)

# Run security tests
vulnerabilities = hallucinator.test_permissions(document)
```

### Working with the Database

```python
from src.infrastructure.database import db
from src.infrastructure.repositories import AuditLogRepository

# Get a session
session = db.get_session()
repo = AuditLogRepository(session)

# Store audit log with embedding
log = repo.create(
    user_id="john.doe",
    action="READ",
    metadata={"document": "Contract_2026.pdf"},
    embedding=embedding_vector
)

# Search by similarity
similar_logs = repo.search_by_embedding(query_embedding, limit=10)
```

## Testing

Run the test suite:

```bash
pytest tests/
```

Run with coverage:

```bash
pytest --cov=src tests/
```

## Project Structure Details

### Domain Layer (`src/domain/`)
Contains core business entities and domain logic:
- `entities.py`: Core data models (AuditRecord, SecurityFinding, etc.)

### Infrastructure Layer (`src/infrastructure/`)
Handles external systems and data persistence:
- `database.py`: PostgreSQL/pgvector database connection
- `content_manager_client.py`: Content Manager API client

### Application Layer (`src/application/`)
Contains the AI agents and business logic:
- `sentinel_agent.py`: Audit log analysis and anomaly detection
- `hallucinator_agent.py`: AI-powered security testing

### Interface Layer (`src/interface/`)
User-facing components:
- `streamlit_app.py`: Interactive web dashboard
- `api.py`: REST API endpoints

## Dependencies

- **streamlit**: Web UI framework
- **pandas**: Data manipulation
- **psycopg2-binary**: PostgreSQL adapter
- **pgvector**: Vector similarity search
- **sqlalchemy**: Database ORM
- **python-dotenv**: Environment variable management
- **requests**: HTTP client
- **openai**: OpenAI API client
- **pytest**: Testing framework

## Development

### Code Quality

Format code with Black:
```bash
black src/
```

Check code style:
```bash
flake8 src/
```

Type checking:
```bash
mypy src/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

[Your License Here]

## Support

For issues and questions, please open an issue in the repository.

## Roadmap

- [ ] Add support for more AI models
- [ ] Implement real-time monitoring
- [ ] Add custom rule engine
- [ ] Integrate with SIEM systems
- [ ] Add automated remediation capabilities
