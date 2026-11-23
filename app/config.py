import os


class Settings:
    app_name: str = os.getenv("APP_NAME", "notes-demo")
    # Assembled from the same POSTGRES_* values the db container uses, so there is one
    # place (.env) to set them. DATABASE_URL wins when it is set (external database).
    database_url: str = os.getenv("DATABASE_URL") or (
        "postgresql://{user}:{password}@{host}:{port}/{db}".format(
            user=os.getenv("POSTGRES_USER", "app"),
            password=os.getenv("POSTGRES_PASSWORD", ""),
            host=os.getenv("POSTGRES_HOST", "db"),
            port=os.getenv("POSTGRES_PORT", "5432"),
            db=os.getenv("POSTGRES_DB", "appdb"),
        )
    )


settings = Settings()
