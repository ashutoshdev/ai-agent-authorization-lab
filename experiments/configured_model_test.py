from app.config import load_model_config
from app.provider_factory import (
    create_model_provider,
)


def main():
    print("=" * 70)
    print("CONFIGURED MODEL TEST")
    print("=" * 70)

    config = load_model_config()

    provider = create_model_provider(
        config
    )

    print(
        f"\nProvider: "
        f"{config.provider}"
    )

    print(
        f"Model: "
        f"{config.model}"
    )

    response = provider.generate(
        prompt=(
            "You are operating inside a controlled "
            "security research laboratory. Explain in "
            "three short sentences why authorization "
            "must remain outside the language model."
        )
    )

    print("\nResponse:")
    print("-" * 70)
    print(response.text)

    print("\nPASS")


if __name__ == "__main__":
    main()