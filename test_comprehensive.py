def test_home_page_has_no_account_controls(application):
    response = application.app.test_client().get("/")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "authForm" not in html
    assert "btnLogin" not in html
    assert "btnRegister" not in html
    assert "btnLogout" not in html
