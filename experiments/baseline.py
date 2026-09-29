from app.agent import Agent
from app.audit import get_events


def main():
    agent_a = Agent("tenant-a")

    print("1. List documents")
    print(agent_a.list_documents())

    print("\n2. Read own document")
    print(agent_a.read_document("doc-a-1"))

    print("\n3. Try another tenant's document")
    print(agent_a.read_document("doc-b-1"))

    print("\n4. Audit events")
    for event in get_events():
        print(event)


if __name__ == "__main__":
    main()