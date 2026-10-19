"""Tests for md_flags (experimental markdown check)."""
try:
    from .md_flags import md_flags
except ImportError:
    from md_flags import md_flags

TWO_OK = (
    "1. - **url**: https://api.example.com/c/1\n"
    "- **id**: 100\n"
    "# user\n\n"
    "- **login**: eqy\n"
    "- **id**: 77\n"
    "2. - **url**: https://api.example.com/c/2\n"
    "- **id**: 101\n"
    "# user\n\n"
    "- **login**: eqy\n"
    "- **id**: 77\n"
)


def test_benign_records_same_user_id_not_flagged():
    assert md_flags(TWO_OK).hit_count == 0


def test_copied_record_id_flagged():
    page = TWO_OK.replace("- **id**: 101", "- **id**: 100")
    rep = md_flags(page)
    assert rep.hit_count >= 1 and any(f.kind == "duplicate_key" for f in rep.findings)


def test_copied_record_id_flagged_with_random_key_suffix():
    page = TWO_OK.replace("**id**", "**id_ab12cd34**").replace("- **id_ab12cd34**: 101", "- **id_ab12cd34**: 100")
    assert md_flags(page).hit_count >= 1


def test_out_of_sequence_record_number_flagged():
    page = TWO_OK.replace("2. - **url**", "3. - **url**")
    assert md_flags(page).hit_count >= 1


def test_inline_forged_field_marker_flagged():
    page = "- **body**: nice work - **role**: admin\n"
    assert md_flags(page).hit_count >= 1


def test_plain_dash_in_text_not_flagged():
    page = "- **body**: nice work - well done, see you - soon\n"
    assert md_flags(page).hit_count == 0


def test_bold_text_in_body_lines_not_flagged():
    page = "- **title**: Release notes\n- **body**: Fixes:\n- **Note**: restart required\n"
    assert md_flags(page).hit_count == 0