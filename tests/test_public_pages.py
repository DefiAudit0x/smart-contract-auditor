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


def test_report_surfaces_redirect_anonymous_and_access_code_sessions_to_admin_login():
    app.config.update(TESTING=True)
    report_paths = (
        "/report/list",
        "/dashboard",
        "/download/example.txt",
        "/download_pdf/example.pdf",
        "/report/interactive/example.txt",
        "/report/view/example.txt",
        "/report/hackerone/example.txt",
    )
    with app.test_client() as client:
        for path in report_paths:
            response = client.get(path, follow_redirects=False)
            assert response.status_code == 302
            assert response.headers["Location"].endswith("/admin/login")

        with client.session_transaction() as session:
            session["authenticated"] = True
            session["access_code"] = "SCA-TEST-0001"

        for path in report_paths:
            response = client.get(path, follow_redirects=False)
            assert response.status_code == 302
            assert response.headers["Location"].endswith("/admin/login")


def test_admin_can_reach_report_list_and_dashboard():
    app.config.update(TESTING=True)
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["admin_authenticated"] = True

        assert client.get("/report/list").status_code == 200
        assert client.get("/dashboard").status_code == 200
