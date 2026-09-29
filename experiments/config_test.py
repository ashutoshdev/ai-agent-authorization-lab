from app.config import load_model_config
from app.provider_factory import (
    create_model_provider,
)


def main():
    print("=" * 70)
    print("MODEL CONFIGURATION TEST")
    print("=" * 70)

    config = load_model_config()

    print("\nConfiguration:")
    print(
        f"  Provider: {config.provider}"
    )

    print(
        f"  Model: {config.model}"
    )

    print(
        f"  Base URL: {config.base_url}"
    )

    print(
        "  API key configured: "
        f"{bool(config.api_key)}"
    )

    provider = create_model_provider(
        config
    )

    print("\nProvider:")
    print(
        f"  {provider.__class__.__name__}"
    )

    print("\nPASS")


if __name__ == "__main__":
    main()