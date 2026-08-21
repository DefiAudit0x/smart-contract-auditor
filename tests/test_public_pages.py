from web_ui import app


def test_methodology_page_explains_review_limits():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        response = client.get("/methodology")

    assert response.status_code == 200
    assert b"security guarantee" in response.data
    assert b"Required review step" in response.data


def test_landing_links_to_methodology_and_review_warning():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        response = client.get("/")

    assert response.status_code == 200
    assert b'href="/methodology"' in response.data
    assert b"Every result needs contextual human review" in response.data


def test_authenticated_workspace_exposes_review_assistance_state():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["authenticated"] = True
        response = client.get("/app")

    assert response.status_code == 200
    assert b"Review assistance" in response.data
    assert b"Start review" in response.data


def test_workspace_tool_menu_links_to_existing_review_pages():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["authenticated"] = True
        response = client.get("/app")

    assert response.status_code == 200
    for route in (b"/report/list", b"/explorer", b"/batch", b"/gas", b"/rules", b"/cicd"):
        assert route in response.data


def test_cicd_page_renders_github_actions_secret_literal():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        response = client.get("/cicd")

    assert response.status_code == 200
    assert b"${{ secrets.AUDITOR_API_KEY }}" in response.data
