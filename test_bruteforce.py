def test_fresh_database_does_not_create_account_tables(application):
    with application.db._connection() as connection:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert "users" not in tables
    assert "failed_logins" not in tables
