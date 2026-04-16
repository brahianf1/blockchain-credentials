from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from portal.config import MOODLE_DB_PREFIX

P = MOODLE_DB_PREFIX


def get_credentials_for_user(db: Session, moodle_user_id: int) -> List[dict]:
    """Return all credentials for a Moodle user, joined with course metadata."""
    query = text(f"""
        SELECT bc.id, bc.courseid, bc.connection_id, bc.invitation_url,
               bc.qr_code_base64, bc.status, bc.timecreated, bc.timemodified,
               c.fullname AS course_name, c.shortname AS course_shortname
        FROM {P}block_credenciales bc
        JOIN {P}course c ON c.id = bc.courseid
        WHERE bc.userid = :moodle_user_id
        ORDER BY bc.timecreated DESC
    """)
    result = db.execute(query, {"moodle_user_id": moodle_user_id})
    return [dict(row._mapping) for row in result]


def get_credential_by_id(
    db: Session, credential_id: int, moodle_user_id: int
) -> Optional[dict]:
    """Return a single credential with ownership check, joined with user and course data."""
    query = text(f"""
        SELECT bc.id, bc.userid, bc.courseid, bc.connection_id,
               bc.invitation_url, bc.qr_code_base64, bc.status,
               bc.timecreated, bc.timemodified,
               c.fullname AS course_name, c.shortname AS course_shortname,
               u.firstname, u.lastname, u.email AS student_email
        FROM {P}block_credenciales bc
        JOIN {P}course c ON c.id = bc.courseid
        JOIN {P}user u ON u.id = bc.userid
        WHERE bc.id = :credential_id AND bc.userid = :moodle_user_id
    """)
    result = db.execute(
        query, {"credential_id": credential_id, "moodle_user_id": moodle_user_id}
    )
    row = result.first()
    return dict(row._mapping) if row else None


def count_credentials_by_status(db: Session, moodle_user_id: int) -> dict:
    """Return credential counts grouped by status for the dashboard stats."""
    query = text(f"""
        SELECT status, COUNT(*) AS count
        FROM {P}block_credenciales
        WHERE userid = :moodle_user_id
        GROUP BY status
    """)
    result = db.execute(query, {"moodle_user_id": moodle_user_id})
    counts: dict = {}
    for row in result:
        mapping = row._mapping
        counts[mapping["status"]] = mapping["count"]
    return counts


def get_user_info(db: Session, moodle_user_id: int) -> Optional[dict]:
    """Return basic user info from Moodle's user table."""
    query = text(f"""
        SELECT id, firstname, lastname, email, username
        FROM {P}user
        WHERE id = :moodle_user_id AND deleted = 0
    """)
    result = db.execute(query, {"moodle_user_id": moodle_user_id})
    row = result.first()
    return dict(row._mapping) if row else None


def get_user_grade(
    db: Session, moodle_user_id: int, course_id: int
) -> Optional[str]:
    """Return the final grade for a user in a specific course, if available."""
    query = text(f"""
        SELECT gg.finalgrade
        FROM {P}grade_grades gg
        JOIN {P}grade_items gi ON gi.id = gg.itemid
        WHERE gg.userid = :moodle_user_id
          AND gi.courseid = :course_id
          AND gi.itemtype = 'course'
        LIMIT 1
    """)
    result = db.execute(
        query, {"moodle_user_id": moodle_user_id, "course_id": course_id}
    )
    row = result.first()
    if row and row._mapping["finalgrade"] is not None:
        return str(round(float(row._mapping["finalgrade"]), 1))
    return None


def get_all_credential_hashes(db: Session) -> List[dict]:
    """Return minimal data for all credentials, used for public hash verification.

    Only fetches the fields needed to compute hashes and display basic info.
    """
    query = text(f"""
        SELECT bc.id, bc.userid, bc.courseid, bc.status,
               bc.timecreated, bc.timemodified,
               c.fullname AS course_name,
               u.firstname, u.lastname
        FROM {P}block_credenciales bc
        JOIN {P}course c ON c.id = bc.courseid
        JOIN {P}user u ON u.id = bc.userid
        ORDER BY bc.timecreated DESC
    """)
    result = db.execute(query)
    return [dict(row._mapping) for row in result]
