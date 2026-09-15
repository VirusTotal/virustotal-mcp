import base64
import copy
import hashlib
import importlib.util
import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("registry", ROOT / "scripts/registry.py")
registry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registry)
CORPORATE, PERSONAL = registry.IDENTITIES
SHA = "a" * 40
PACKAGE_SOURCE_SHA = "c26eb5127d6e6a48fd241330cfc0c2d6c3f3c2ae"
MARKER = "SYNTHETIC_SECRET_MUST_NOT_ESCAPE"
# Independently fixed from each repository's observed GitHub sub_claim_prefix.
SUBJECTS = {
    CORPORATE: "repo:VirusTotal@7701252/virustotal-mcp@1361592455:ref:refs/heads/main",
    PERSONAL: "repo:king-tero@4201239/vt-mcp@1359828317:ref:refs/heads/main",
}


def manifest(repository, version=None):
    result = json.loads((ROOT / "server.json").read_text())
    selected = registry.IDENTITIES[repository]
    result.update(name=selected["name"], version=version or selected["version"])
    result.pop("repository", None)
    if repository == PERSONAL or version in {"0.8.2", "0.8.3"}:
        result.pop("icons", None)
        result["remotes"][0]["headers"] = [
            {
                "name": "Authorization",
                "description": "Static VTAI agent token. Get free access at "
                "https://ai.virustotal.com/connect/mcp.",
                "isRequired": True,
                "isSecret": True,
                "value": "Bearer {VTAI_TOKEN}",
                "variables": {
                    "VTAI_TOKEN": {
                        "description": "Your VTAI token, without the Bearer prefix. "
                        "Store it in the client's protected credential settings.",
                        "isRequired": True,
                        "isSecret": True,
                    }
                },
            }
        ]
    if version in {"0.8.3", "0.8.4"}:
        result["packages"][0]["version"] = "0.8.3"
    if repository == PERSONAL or version == "0.8.2":
        result.pop("packages", None)
    if repository == PERSONAL:
        result["repository"] = {
            "url": f"https://github.com/{PERSONAL}",
            "source": "github",
            "id": "1359828317",
        }
    return result


def entry(repository, status, version=None):
    if status == "absent":
        return None
    official = {"status": status}
    if status != "active":
        official["statusMessage"] = "Previous public lifecycle message"
    if repository == PERSONAL and status == "deleted":
        official["statusMessage"] = registry.RETIRE_MESSAGES[PERSONAL]
    return {"server": manifest(repository, version), "_meta": {registry.OFFICIAL: official}}


def token(repository, **changes):
    now = int(time.time())
    claims = {
        "iss": "mcp-registry",
        "auth_method": "github-oidc",
        "auth_method_sub": SUBJECTS[repository],
        "permissions": [
            {
                "action": "publish",
                "resource": registry.IDENTITIES[repository]["name"].split("/")[0] + "/*",
            }
        ],
        "iat": now,
        "nbf": now,
        "exp": now + 1800,
        **changes,
    }

    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return {
        "token": encode({"alg": "EdDSA"}) + "." + encode(claims) + ".synthetic",
        "method": "github-oidc",
        "registry": registry.REGISTRY,
    }


@pytest.fixture
def harness(tmp_path, monkeypatch):
    cwd, home, temporary = (tmp_path / name for name in ("checkout", "home", "runner"))
    for path in (cwd, home, temporary):
        path.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    env = {
        "HOME": str(home),
        "RUNNER_TEMP": str(temporary),
        "PATH": "/usr/bin",
        "GITHUB_REPOSITORY": CORPORATE,
        "GITHUB_REPOSITORY_ID": "1361592455",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": f"{CORPORATE}/.github/workflows/mcp-registry.yml@refs/heads/main",
        "GITHUB_SHA": SHA,
        "REVIEWED_SHA": SHA,
        "REGISTRY_OPERATION": "verify-identity",
        "GH_TOKEN": MARKER,
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": MARKER,
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://synthetic.invalid/oidc",
        "GH_DEBUG": "api",
        "GH_FORCE_TTY": "1",
        "HTTPS_PROXY": "https://synthetic.invalid",
    }
    monkeypatch.setattr(registry.os, "environ", env)
    state = SimpleNamespace(
        env=env,
        cwd=cwd,
        home=home,
        temporary=temporary,
        calls=[],
        reads=[],
        entries={CORPORATE: None, PERSONAL: entry(PERSONAL, "active")},
        previous={
            version: entry(CORPORATE, "active", version) for version in ("0.8.2", "0.8.3", "0.8.4")
        },
        pypi_reads=[],
        gh_override={},
        claims={},
        saved_changes={},
        credential_mode=0o600,
        fail=None,
        apply=True,
        after_mutation=None,
    )
    state.checksums = (
        f"{'1' * 64}  vt_mcp-0.8.4-py3-none-any.whl\n{'2' * 64}  vt_mcp-0.8.4.tar.gz\n"
    ).encode()
    manifest_sha = hashlib.sha256(state.checksums).hexdigest()
    monkeypatch.setitem(
        registry.IDENTITIES[CORPORATE],
        "package_release",
        {
            "version": "0.8.4",
            "source_sha": PACKAGE_SOURCE_SHA,
            "tag_object_sha": "b" * 40,
            "manifest_sha256": manifest_sha,
        },
    )
    state.pypi = {
        "info": {
            "name": "vt-mcp",
            "version": "0.8.4",
            "description": "<!-- mcp-name: io.github.VirusTotal/virustotal-mcp -->\n",
        },
        "urls": [
            {
                "filename": "vt_mcp-0.8.4-py3-none-any.whl",
                "packagetype": "bdist_wheel",
                "digests": {"sha256": "1" * 64},
                "yanked": False,
            },
            {
                "filename": "vt_mcp-0.8.4.tar.gz",
                "packagetype": "sdist",
                "digests": {"sha256": "2" * 64},
                "yanked": False,
            },
        ],
    }
    state.release_responses = {
        f"repos/{CORPORATE}/git/ref/tags/v0.8.4": {"object": {"type": "tag", "sha": "b" * 40}},
        f"repos/{CORPORATE}/git/tags/{'b' * 40}": {
            "tag": "v0.8.4",
            "object": {"type": "commit", "sha": PACKAGE_SOURCE_SHA},
            "message": f"Release\nSHA256SUMS-SHA256: {manifest_sha}\n",
        },
        f"repos/{CORPORATE}/releases/tags/v0.8.4": {
            "tag_name": "v0.8.4",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-09-12T19:00:00Z",
            "assets": [
                {
                    "id": 1,
                    "name": "SHA256SUMS",
                    "state": "uploaded",
                    "digest": f"sha256:{manifest_sha}",
                },
                {
                    "id": 2,
                    "name": "vt_mcp-0.8.4-py3-none-any.whl",
                    "state": "uploaded",
                    "digest": f"sha256:{'1' * 64}",
                },
                {
                    "id": 3,
                    "name": "vt_mcp-0.8.4.tar.gz",
                    "state": "uploaded",
                    "digest": f"sha256:{'2' * 64}",
                },
            ],
        },
        f"repos/{CORPORATE}/releases/assets/1": state.checksums,
    }

    def select(repository, operation="verify-identity"):
        env.update(
            GITHUB_REPOSITORY=repository,
            GITHUB_REPOSITORY_ID=str(registry.IDENTITIES[repository]["id"]),
            GITHUB_WORKFLOW_REF=f"{repository}/.github/workflows/mcp-registry.yml@refs/heads/main",
            REGISTRY_OPERATION=operation,
        )
        (cwd / "server.json").write_text(json.dumps(manifest(repository)))

    def read(path):
        state.reads.append(path)
        assert path.endswith("?include_deleted=true")
        repository = next(r for r, s in registry.IDENTITIES.items() if s["name"] in unquote(path))
        current = copy.deepcopy(state.entries[repository])
        if path.endswith("/versions?include_deleted=true"):
            rows = [current] if current else []
            if repository == CORPORATE:
                rows.extend(copy.deepcopy(row) for row in state.previous.values() if row)
            return {
                "servers": rows,
                "metadata": {"count": len(rows)},
            }
        if repository == CORPORATE:
            for version, row in state.previous.items():
                if f"/versions/{version}?" in path:
                    return copy.deepcopy(row)
        return current

    def run(argv, *, env, capture_output, timeout, check, stdin):
        state.calls.append((argv, env, timeout))
        assert capture_output and check is False and stdin == subprocess.DEVNULL
        assert MARKER not in json.dumps(argv)
        assert not {"GH_DEBUG", "GH_FORCE_TTY", "HTTPS_PROXY"} & env.keys()
        repository = state.env["GITHUB_REPOSITORY"]
        selected = registry.IDENTITIES[repository]
        if argv[0] == "gh":
            assert argv[1:7] == ["api", "--hostname", "github.com", "--method", "GET", argv[6]]
            prefix = f"repos/{repository}"
            base_repo = {"id": selected["id"], "full_name": repository}
            responses = {
                prefix: {**base_repo, "private": repository == CORPORATE},
                prefix + "/git/ref/heads/main": {"object": {"sha": SHA}},
                prefix
                + f"/actions/workflows/ci.yml/runs?head_sha={SHA}"
                + "&event=push&branch=main&per_page=100": {
                    "workflow_runs": [
                        {
                            "head_sha": SHA,
                            "head_branch": "main",
                            "event": "push",
                            "status": "completed",
                            "conclusion": "success",
                            "path": ".github/workflows/ci.yml",
                            "repository": base_repo,
                            "head_repository": base_repo,
                        }
                    ]
                },
            }
            responses.update(state.release_responses)
            response = state.gh_override.get(argv[6], responses[argv[6]])
            if isinstance(response, bytes):
                assert argv[-2:] == ["-H", "Accept: application/octet-stream"]
            return SimpleNamespace(
                returncode=0,
                stdout=response if isinstance(response, bytes) else json.dumps(response).encode(),
                stderr=b"",
            )
        assert "GH_TOKEN" not in env
        operation = argv[1]
        credential = home / ".config/mcp-publisher/token.json"
        if operation == "login":
            assert len([c for c in state.calls if c[0][0] == "gh"]) in {3, 7}
            credential.parent.mkdir(parents=True, exist_ok=True)
            credential.write_text(
                json.dumps({**token(repository, **state.claims), **state.saved_changes})
            )
            credential.chmod(state.credential_mode)
        if operation in ("publish", "status"):
            intent = json.loads((temporary / "registry-mutation-intent.json").read_text())
            assert intent["sha"] == SHA and intent["operation"] == state.env["REGISTRY_OPERATION"]
            assert "--all-versions" not in argv
            if state.apply:
                if operation == "publish":
                    state.entries[repository] = entry(repository, "active")
                else:
                    assert argv[2:4] in (["--status", "active"], ["--status", "deleted"])
                    new_status = argv[3]
                    state.entries[repository] = entry(repository, new_status)
                    if new_status == "deleted":
                        assert argv[4:6] == ["--message", registry.RETIRE_MESSAGES[repository]]
                        state.entries[repository]["_meta"][registry.OFFICIAL]["statusMessage"] = (
                            registry.RETIRE_MESSAGES[repository]
                        )
                    else:
                        assert "--message" not in argv
                    assert argv[-2:] == [selected["name"], selected["version"]]
            if state.after_mutation:
                state.after_mutation()
        if operation == state.fail:
            raise subprocess.TimeoutExpired(
                argv, timeout, output=MARKER.encode(), stderr=MARKER.encode()
            )
        return SimpleNamespace(returncode=0, stdout=MARKER.encode(), stderr=MARKER.encode())

    select(CORPORATE)

    def pypi_read(version):
        state.pypi_reads.append(version)
        return copy.deepcopy(state.pypi)

    monkeypatch.setattr(registry, "registry_get", read)
    monkeypatch.setattr(registry, "pypi_get", pypi_read)
    monkeypatch.setattr(registry.subprocess, "run", run)
    state.select = select
    state.result = lambda: json.loads((temporary / "registry-result.json").read_text())
    state.mutations = lambda: [c[0] for c in state.calls if c[0][1] in {"publish", "status"}]
    return state


def test_verify_identity_authenticates_but_never_changes_entries(harness, capsys):
    assert registry.main([]) == 0
    result = harness.result()
    assert result["status"] == "verified" and result["identity_verified"]
    assert result["before"] == result["after"] and len(harness.reads) == 14
    assert not result["mutation_attempted"] and not harness.mutations()
    assert result["credential_cleanup"] == "removed"
    assert not registry.credential_paths()[0].exists()
    assert MARKER not in capsys.readouterr().out
    assert MARKER not in json.dumps(result)


def test_validation_keeps_official_publisher_and_requires_no_identity_token(harness):
    assert registry.main(["validate"]) == 0
    assert [c[0][1:] for c in harness.calls] == [["validate", "server.json"]]
    assert not harness.reads and harness.result()["status"] == "validated"


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_REPOSITORY", "untrusted/repo"),
        ("GITHUB_REPOSITORY_ID", "1"),
        ("REVIEWED_SHA", "a" * 39),
        ("GITHUB_REF", "refs/heads/other"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_WORKFLOW_REF", "wrong"),
        ("REGISTRY_OPERATION", "delete-everything"),
    ],
)
def test_context_rejected_before_any_authentication(harness, key, value):
    harness.env[key] = value
    assert registry.main([]) == 1
    assert not harness.calls and not harness.reads


@pytest.mark.parametrize("change", ["id", "main", "ci", "private"])
def test_github_preflight_precedes_oidc(harness, change):
    if change == "private":
        harness.select(PERSONAL)
    prefix = f"repos/{harness.env['GITHUB_REPOSITORY']}"
    if change in ("id", "private"):
        harness.gh_override[prefix] = {
            "id": 1 if change == "id" else 1359828317,
            "full_name": harness.env["GITHUB_REPOSITORY"],
            "private": True,
        }
    elif change == "main":
        harness.gh_override[prefix + "/git/ref/heads/main"] = {"object": {"sha": "b" * 40}}
    else:
        harness.gh_override[
            prefix
            + f"/actions/workflows/ci.yml/runs?head_sha={SHA}&event=push&branch=main&per_page=100"
        ] = {"workflow_runs": []}
    assert registry.main([]) == 1
    assert all(c[0][0] == "gh" for c in harness.calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", {"url": "https://private.invalid"}),
        ("packages", []),
        ("version", "0.8.6"),
        ("remotes", [{"url": "https://other.invalid"}]),
    ],
)
def test_contract_pins_entire_remote_and_package_manifest(harness, field, value):
    data = manifest(CORPORATE)
    data[field] = value
    (harness.cwd / "server.json").write_text(json.dumps(data))
    assert registry.main([]) == 1 and not harness.calls


@pytest.mark.parametrize(
    "repository,operation,own,counterpart,outcome",
    [
        (CORPORATE, "publish", "absent", "deleted", "completed"),
        (CORPORATE, "publish", "active", "deleted", "noop"),
        (PERSONAL, "retire", "active", "absent", "completed"),
        (PERSONAL, "retire", "deprecated", "active", "completed"),
        (PERSONAL, "retire", "deleted", "active", "noop"),
        (CORPORATE, "restore", "deleted", "deleted", "completed"),
        (CORPORATE, "restore", "active", "deleted", "noop"),
    ],
)
def test_success_and_same_status_idempotence(
    harness, repository, operation, own, counterpart, outcome
):
    harness.select(repository, operation)
    other = next(r for r in registry.IDENTITIES if r != repository)
    harness.entries = {repository: entry(repository, own), other: entry(other, counterpart)}
    assert registry.main([]) == 0
    result = harness.result()
    assert result["status"] == outcome and len(harness.mutations()) == (outcome == "completed")
    assert result["after"][other] == result["before"][other]
    assert result["credential_cleanup"] == "removed"


@pytest.mark.parametrize(
    "operation,own,counterpart,error",
    [
        ("publish", "absent", "active", "counterpart_reserves_remote_url"),
        ("publish", "absent", "deprecated", "counterpart_reserves_remote_url"),
        ("restore", "deleted", "active", "counterpart_reserves_remote_url"),
        ("restore", "deleted", "deprecated", "counterpart_reserves_remote_url"),
        ("publish", "deleted", "deleted", "existing_version_requires_restore"),
        ("publish", "deprecated", "deleted", "existing_version_requires_restore"),
        ("retire", "absent", "deleted", "own_version_missing"),
        ("restore", "absent", "deleted", "own_version_missing"),
    ],
)
def test_invalid_transitions_do_not_mutate(harness, operation, own, counterpart, error):
    harness.select(CORPORATE, operation)
    harness.entries = {CORPORATE: entry(CORPORATE, own), PERSONAL: entry(PERSONAL, counterpart)}
    assert registry.main([]) == 1
    assert harness.result()["error"] == error and not harness.mutations()
    assert not registry.credential_paths()[0].exists()


@pytest.mark.parametrize(
    "problem", ["extra_version", "wrong_manifest", "count", "cursor", "disagreement"]
)
def test_inventory_drift_fails_closed(harness, monkeypatch, problem):
    original = registry.registry_get

    def changed(path):
        value = original(path)
        if "king-tero" not in path:
            return value
        if "servers" in (value or {}):
            if problem == "extra_version":
                value["servers"] *= 2
                value["metadata"]["count"] = 2
            if problem == "wrong_manifest":
                value["servers"][0]["server"]["version"] = "0.8.1"
            if problem == "count":
                value["metadata"]["count"] = 0
            if problem == "cursor":
                value["metadata"]["nextCursor"] = "unfinished"
        elif problem == "disagreement":
            return None
        return value

    monkeypatch.setattr(registry, "registry_get", changed)
    assert registry.main([]) == 1 and not harness.mutations()
    assert harness.result()["credential_cleanup"] == "removed"


@pytest.mark.parametrize(
    "claims,error",
    [
        ({"auth_method_sub": "repo:other/repo:ref:refs/heads/main"}, "credential_subject_mismatch"),
        ({"auth_method": "github"}, "credential_rejected"),
        ({"permissions": [{"action": "edit", "resource": "*"}]}, "credential_permissions_mismatch"),
        ({"iat": True}, "credential_time_invalid"),
        ({"exp": 1}, "credential_time_invalid"),
        ({"nbf": 9999999999}, "credential_time_invalid"),
    ],
)
def test_oidc_claims_must_match_this_job(harness, capsys, claims, error):
    harness.claims = claims
    assert registry.main([]) == 1
    assert harness.result()["error"] == error and not harness.reads
    assert not registry.credential_paths()[0].exists()
    assert MARKER not in capsys.readouterr().out
    assert "auth_method_sub" not in json.dumps(harness.result())


@pytest.mark.parametrize("repository", [CORPORATE, PERSONAL])
def test_observed_immutable_subject_succeeds_without_registry_mutation(harness, repository):
    harness.select(repository)
    assert registry.main([]) == 0
    assert harness.result()["identity_verified"] and not harness.mutations()
    assert not registry.credential_paths()[0].exists()


@pytest.mark.parametrize("repository", [CORPORATE, PERSONAL])
@pytest.mark.parametrize("changed", ["legacy", "owner_id", "repository_id", "owner", "ref"])
def test_other_or_legacy_subject_rejected_exactly(harness, capsys, repository, changed):
    harness.select(repository)
    subject = SUBJECTS[repository]
    if changed == "legacy":
        subject = f"repo:{repository}:ref:refs/heads/main"
    elif changed == "owner_id":
        subject = subject.replace("@7701252/", "@7701253/").replace("@4201239/", "@4201240/")
    elif changed == "repository_id":
        subject = subject.replace("@1361592455:", "@1361592456:").replace(
            "@1359828317:", "@1359828318:"
        )
    elif changed == "owner":
        subject = subject.replace("VirusTotal@", "other@").replace("king-tero@", "other@")
    else:
        subject = subject.replace("refs/heads/main", "refs/heads/other")
    harness.claims = {"auth_method_sub": subject}
    assert registry.main([]) == 1
    result = harness.result()
    assert result["error"] == "credential_subject_mismatch"
    assert not result["mutation_attempted"] and result["credential_cleanup"] == "removed"
    assert not harness.reads and not harness.mutations()
    assert subject not in capsys.readouterr().out and subject not in json.dumps(result)


@pytest.mark.parametrize("problem", ["mode", "registry", "method", "malformed"])
def test_new_credential_rejected_and_cleaned(harness, problem):
    if problem == "mode":
        harness.credential_mode = 0o644
    else:
        harness.saved_changes = (
            {"registry": "https://other.invalid"}
            if problem == "registry"
            else {"method": "github"}
            if problem == "method"
            else {"token": MARKER}
        )
    assert registry.main([]) == 1 and not registry.credential_paths()[0].exists()
    assert not harness.mutations()


@pytest.mark.parametrize("index", [0, 1, 2, 4])
def test_existing_credentials_never_read_overwritten_or_logged_out(harness, index):
    path = registry.credential_paths()[index]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(MARKER)
    assert registry.main([]) == 1
    assert path.read_text() == MARKER
    assert all(c[0][0] == "gh" for c in harness.calls)


@pytest.mark.parametrize("failure", ["login", "logout", "publish"])
def test_timeout_cleanup_privacy_and_no_ambiguous_retry(harness, capsys, failure):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")
    harness.fail = failure
    code = registry.main([])
    assert code == (0 if failure == "logout" else 1)
    result = harness.result()
    assert not registry.credential_paths()[0].exists()
    assert result["credential_cleanup"] == "removed"
    assert len(harness.mutations()) == (failure != "login")
    if failure == "publish":
        assert result["reconciliation_required"] and result["mutation_attempted"]
        assert "after" not in result
        before = len(harness.calls)
        assert registry.main([]) == 1 and len(harness.calls) == before
    assert MARKER not in capsys.readouterr().out and MARKER not in json.dumps(result)


def test_post_read_stale_state_requires_reconciliation_not_retry(harness):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")
    harness.apply = False
    assert registry.main([]) == 1
    assert harness.result()["error"] == "postcondition_failed"
    assert harness.result()["reconciliation_required"] and len(harness.mutations()) == 1


def test_counterpart_changed_after_mutation_is_preserved_error(harness):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")
    harness.after_mutation = lambda: harness.entries.update({PERSONAL: entry(PERSONAL, "active")})
    assert registry.main([]) == 1
    assert harness.result()["error"] == "counterpart_changed" and len(harness.mutations()) == 1


def test_publish_keeps_previous_manifests_and_uses_existing_package(harness):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")
    assert registry.main([]) == 0
    result = harness.result()
    for version, manifest_sha in (
        ("0.8.2", "294e3daa8f45e8f6b6050ab7cce140489272844c911afe6e3aca60843b0aa0e8"),
        ("0.8.3", "fdcfa9f92f6945e38bfecc65d5f22c5ce2caf908573bc39a059a79fd3daae40b"),
        ("0.8.4", "5295fde5e5c1dcab1061763236c332d8ef1ec4ec7b108d17da638cad0873f04d"),
    ):
        previous = f"{CORPORATE}@{version}"
        assert result["before"][previous] == result["after"][previous]
        assert result["after"][previous]["manifest_sha256"] == manifest_sha
        assert result["after"][previous]["status"] == "active"
    assert result["before"][PERSONAL] == result["after"][PERSONAL]
    assert result["after"][PERSONAL]["status"] == "deleted"
    assert result["after"][CORPORATE]["version"] == "0.8.5"
    assert result["pypi"]["version"] == "0.8.4"
    assert result["pypi"]["source_sha"] == PACKAGE_SOURCE_SHA != result["sha"]
    assert result["pypi"]["files"] == {
        "vt_mcp-0.8.4-py3-none-any.whl": "1" * 64,
        "vt_mcp-0.8.4.tar.gz": "2" * 64,
    }
    assert harness.pypi_reads == ["0.8.4"]


def test_publication_allows_registry_to_update_computed_latest_flag(harness):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")
    harness.previous["0.8.4"]["_meta"][registry.OFFICIAL]["isLatest"] = True

    def update_latest():
        harness.previous["0.8.4"]["_meta"][registry.OFFICIAL]["isLatest"] = False
        harness.entries[CORPORATE]["_meta"][registry.OFFICIAL]["isLatest"] = True

    harness.after_mutation = update_latest
    assert registry.main([]) == 0
    assert len(harness.mutations()) == 1
    assert harness.result()["status"] == "completed"


@pytest.mark.parametrize("after_mutation", [False, True])
@pytest.mark.parametrize("drift", ["missing", "status", "manifest"])
@pytest.mark.parametrize("version", ["0.8.2", "0.8.3", "0.8.4"])
def test_previous_version_drift_is_rejected(harness, drift, after_mutation, version):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")

    def change():
        if drift == "missing":
            harness.previous[version] = None
        elif drift == "status":
            harness.previous[version] = entry(CORPORATE, "deleted", version)
        else:
            harness.previous[version]["server"]["title"] = "Changed"

    if after_mutation:
        harness.after_mutation = change
    else:
        change()
    assert registry.main([]) == 1
    result = harness.result()
    assert result["error"] == (
        "manifest_contract_mismatch" if drift == "manifest" else "previous_version_status_changed"
    )
    assert result["mutation_attempted"] is after_mutation
    assert result["reconciliation_required"] is after_mutation
    assert len(harness.mutations()) == int(after_mutation)


@pytest.mark.parametrize("version", ["0.8.1", "0.8.6"])
def test_no_other_corporate_version_is_accepted(harness, version):
    harness.previous["0.8.2"]["server"]["version"] = version
    assert registry.main([]) == 1
    assert harness.result()["error"] == "unexpected_registry_versions"
    assert not harness.mutations()


def test_personal_restore_is_blocked_by_existing_corporate_082(harness):
    harness.select(PERSONAL, "restore")
    harness.entries = {PERSONAL: entry(PERSONAL, "deleted"), CORPORATE: None}
    assert registry.main([]) == 1
    assert harness.result()["error"] == "counterpart_reserves_remote_url"
    assert not harness.mutations() and not harness.pypi_reads


def test_personal_retirement_message_is_pinned_before_new_publication(harness):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")
    harness.entries[PERSONAL]["_meta"][registry.OFFICIAL]["statusMessage"] = "Changed"
    assert registry.main([]) == 1
    assert harness.result()["error"] == "personal_retirement_changed"
    assert not harness.mutations()


@pytest.mark.parametrize("operation", ["verify-identity", "retire"])
def test_recovery_and_identity_do_not_require_pypi(harness, monkeypatch, operation):
    harness.select(CORPORATE, operation)
    harness.entries = {PERSONAL: entry(PERSONAL, "deleted"), CORPORATE: entry(CORPORATE, "active")}

    def unavailable(*args):
        pytest.fail("Recovery must not depend on PyPI availability")

    monkeypatch.setattr(registry, "pypi_get", unavailable)
    assert registry.main([]) == 0
    assert "pypi" not in harness.result()


@pytest.mark.parametrize("operation", ["publish", "restore"])
@pytest.mark.parametrize(
    "problem",
    [
        "unavailable",
        "name",
        "version",
        "marker",
        "duplicate_marker",
        "partial",
        "duplicate",
        "extra",
        "yanked",
        "type",
        "invalid_hash",
        "wrong_hash",
    ],
)
def test_pypi_gate_rejects_before_oidc(harness, monkeypatch, operation, problem):
    harness.select(CORPORATE, operation)
    harness.entries = {
        PERSONAL: entry(PERSONAL, "deleted"),
        CORPORATE: entry(CORPORATE, "deleted") if operation == "restore" else None,
    }
    if problem == "unavailable":

        def unavailable(*args):
            raise registry.Rejected("pypi_version_not_available")

        monkeypatch.setattr(registry, "pypi_get", unavailable)
    elif problem in {"name", "version"}:
        harness.pypi["info"][problem] = "other"
    elif problem == "marker":
        harness.pypi["info"]["description"] = "<!-- mcp-name: io.github.other/server -->"
    elif problem == "duplicate_marker":
        harness.pypi["info"]["description"] *= 2
    elif problem == "partial":
        harness.pypi["urls"].pop()
    elif problem == "duplicate":
        harness.pypi["urls"][1] = copy.deepcopy(harness.pypi["urls"][0])
    elif problem == "extra":
        harness.pypi["urls"].append(copy.deepcopy(harness.pypi["urls"][0]))
    elif problem == "yanked":
        harness.pypi["urls"][0]["yanked"] = True
    elif problem == "type":
        harness.pypi["urls"][0]["packagetype"] = "sdist"
    else:
        harness.pypi["urls"][0]["digests"]["sha256"] = (
            "z" * 64 if problem == "invalid_hash" else "3" * 64
        )
    assert registry.main([]) == 1
    assert harness.result()["phase"] == "pypi_preflight"
    assert not harness.result()["mutation_attempted"]
    assert not harness.reads and not registry.credential_paths()[0].exists()
    assert all(c[0][0] == "gh" for c in harness.calls)


@pytest.mark.parametrize(
    "problem",
    [
        "lightweight_tag",
        "moved_tag",
        "wrong_source",
        "unpinned_manifest",
        "draft",
        "prerelease",
        "asset_names",
        "asset_hash",
        "manifest_hash",
        "duplicate_manifest_name",
    ],
)
def test_release_provenance_must_match_public_package(harness, problem):
    harness.select(CORPORATE, "publish")
    harness.entries[PERSONAL] = entry(PERSONAL, "deleted")
    prefix = f"repos/{CORPORATE}"
    tag = harness.release_responses[f"{prefix}/git/tags/{'b' * 40}"]
    release = harness.release_responses[f"{prefix}/releases/tags/v0.8.4"]
    if problem == "lightweight_tag":
        harness.release_responses[f"{prefix}/git/ref/tags/v0.8.4"]["object"]["type"] = "commit"
    elif problem == "moved_tag":
        harness.release_responses[f"{prefix}/git/ref/tags/v0.8.4"]["object"]["sha"] = "c" * 40
    elif problem == "wrong_source":
        # A metadata commit is not a replacement package release.
        tag["object"]["sha"] = SHA
    elif problem == "unpinned_manifest":
        tag["message"] = "No reviewed checksum"
    elif problem in {"draft", "prerelease"}:
        release[problem] = True
    elif problem == "asset_names":
        release["assets"][2]["name"] = "unreviewed.tar.gz"
    elif problem == "asset_hash":
        release["assets"][2]["digest"] = "sha256:" + "3" * 64
    elif problem == "manifest_hash":
        harness.release_responses[f"{prefix}/releases/assets/1"] += b"\n"
    else:
        changed = (harness.checksums.decode().splitlines()[0] + "\n") * 2
        raw = changed.encode()
        harness.release_responses[f"{prefix}/releases/assets/1"] = raw
        tag["message"] = f"SHA256SUMS-SHA256: {hashlib.sha256(raw).hexdigest()}\n"
    assert registry.main([]) == 1
    assert harness.result()["phase"] == "pypi_preflight"
    assert not harness.reads and not harness.mutations()
    assert all(c[0][0] == "gh" for c in harness.calls)


def test_manifest_uses_only_a_path_for_stdio_credential():
    value = manifest(CORPORATE)
    (package,) = value["packages"]
    assert package["registryType"] == "pypi" and package["identifier"] == "vt-mcp"
    assert package["version"] == "0.8.4" and value["version"] == "0.8.5"
    assert package["transport"] == {"type": "stdio"} and package["runtimeHint"] == "uvx"
    (setting,) = package["environmentVariables"]
    assert setting["name"] == "VTAI_TOKEN_FILE"
    assert setting["isRequired"] is True and setting.get("isSecret", False) is False
    assert setting["format"] == "filepath" and setting["placeholder"].startswith("/")
    assert "value" not in setting and "default" not in setting
    assert "repository" not in value
    assert value["remotes"] == [{"type": "streamable-http", "url": "https://ai.virustotal.com/mcp"}]
    assert value["icons"] == [
        {"src": "https://ai.virustotal.com/logo.svg", "mimeType": "image/svg+xml", "sizes": ["any"]}
    ]


def test_workflow_keeps_publisher_pin_scoped_oidc_and_sanitized_artifact():
    text = (ROOT / ".github/workflows/mcp-registry.yml").read_text()
    assert text.count("a06c9096dcb9727c13555b6be26c7effa707b01f06a4c561ba7a3635443cf2cc") == 2
    assert "options: [verify-identity, publish, retire, restore]" in text
    assert (
        text.count("id-token: write") == 1 and "id-token: write" not in text.split("  registry:")[0]
    )
    assert '"$RUNNER_TEMP/mcp-publisher"' not in text
    assert "registry-mutation-intent.json" in text and "token.json" not in text
