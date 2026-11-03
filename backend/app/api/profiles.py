import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.profile import ScanProfile, ScanProgram
from app.schemas.scan import (
    ScanProfileCreateRequest,
    ScanProfileUpdateRequest,
    ScanProfileResponse,
    ScanProgramCreateRequest,
    ScanProgramUpdateRequest,
    ScanProgramResponse,
)

router = APIRouter(prefix="/api", tags=["profiles", "programs"])


# =============================================================================
# SCAN PROFILES API
# =============================================================================

@router.get("/profiles", response_model=List[ScanProfileResponse])
def list_profiles(db: Session = Depends(get_db)):
    profiles = db.query(ScanProfile).order_by(ScanProfile.is_builtin.desc(), ScanProfile.name.asc()).all()
    return profiles


@router.get("/profiles/{profile_id}", response_model=ScanProfileResponse)
def get_profile(profile_id: str, db: Session = Depends(get_db)):
    profile = db.get(ScanProfile, profile_id)
    if not profile:
        raise HTTPException(404, "Scan profile not found")
    return profile


@router.post("/profiles", response_model=ScanProfileResponse, status_code=201)
def create_profile(req: ScanProfileCreateRequest, db: Session = Depends(get_db)):
    existing = db.query(ScanProfile).filter(ScanProfile.name == req.name.strip()).first()
    if existing:
        raise HTTPException(409, f"A profile named '{req.name.strip()}' already exists")

    profile = ScanProfile(
        name=req.name.strip(),
        description=req.description,
        is_builtin=False,
        is_default=False,
        modules=req.modules,
        max_depth=req.max_depth or 2,
        max_urls=req.max_urls or 50,
        max_parameters=req.max_parameters or 50,
        request_rate=req.request_rate or 5.0,
        concurrency=req.concurrency or 2,
        request_timeout=req.request_timeout or 10.0,
        allowed_http_methods=req.allowed_http_methods or ["GET", "POST"],
        enable_browser_discovery=req.enable_browser_discovery if req.enable_browser_discovery is not None else True,
        send_payloads=req.send_payloads if req.send_payloads is not None else True,
        auth_config=req.auth_config,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@router.put("/profiles/{profile_id}", response_model=ScanProfileResponse)
def update_profile(profile_id: str, req: ScanProfileUpdateRequest, db: Session = Depends(get_db)):
    profile = db.get(ScanProfile, profile_id)
    if not profile:
        raise HTTPException(404, "Scan profile not found")

    if profile.is_builtin:
        raise HTTPException(403, "Built-in profiles cannot be modified. You can duplicate this profile instead.")

    if req.name and req.name.strip() != profile.name:
        existing = db.query(ScanProfile).filter(ScanProfile.name == req.name.strip(), ScanProfile.id != profile_id).first()
        if existing:
            raise HTTPException(409, f"A profile named '{req.name.strip()}' already exists")
        profile.name = req.name.strip()

    if req.description is not None:
        profile.description = req.description
    if req.modules is not None:
        profile.modules = req.modules
    if req.max_depth is not None:
        profile.max_depth = req.max_depth
    if req.max_urls is not None:
        profile.max_urls = req.max_urls
    if req.max_parameters is not None:
        profile.max_parameters = req.max_parameters
    if req.request_rate is not None:
        profile.request_rate = req.request_rate
    if req.concurrency is not None:
        profile.concurrency = req.concurrency
    if req.request_timeout is not None:
        profile.request_timeout = req.request_timeout
    if req.allowed_http_methods is not None:
        profile.allowed_http_methods = req.allowed_http_methods
    if req.enable_browser_discovery is not None:
        profile.enable_browser_discovery = req.enable_browser_discovery
    if req.send_payloads is not None:
        profile.send_payloads = req.send_payloads
    if req.auth_config is not None:
        profile.auth_config = req.auth_config

    profile.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(profile)
    return profile


@router.post("/profiles/{profile_id}/duplicate", response_model=ScanProfileResponse, status_code=201)
def duplicate_profile(profile_id: str, db: Session = Depends(get_db)):
    original = db.get(ScanProfile, profile_id)
    if not original:
        raise HTTPException(404, "Scan profile not found")

    # Generate unique name
    base_name = f"{original.name} (Copy)"
    counter = 1
    new_name = base_name
    while db.query(ScanProfile).filter(ScanProfile.name == new_name).first():
        counter += 1
        new_name = f"{original.name} (Copy {counter})"

    clone = ScanProfile(
        name=new_name,
        description=f"Duplicate of {original.name}. {original.description or ''}".strip(),
        is_builtin=False,
        is_default=False,
        modules=list(original.modules or []),
        max_depth=original.max_depth,
        max_urls=original.max_urls,
        max_parameters=original.max_parameters,
        request_rate=original.request_rate,
        concurrency=original.concurrency,
        request_timeout=original.request_timeout,
        allowed_http_methods=list(original.allowed_http_methods or ["GET", "POST"]),
        enable_browser_discovery=original.enable_browser_discovery,
        send_payloads=original.send_payloads,
        auth_config=original.auth_config,
    )
    db.add(clone)
    db.commit()
    db.refresh(clone)
    return clone


@router.delete("/profiles/{profile_id}")
def delete_profile(profile_id: str, db: Session = Depends(get_db)):
    profile = db.get(ScanProfile, profile_id)
    if not profile:
        raise HTTPException(404, "Scan profile not found")

    if profile.is_builtin:
        raise HTTPException(403, "Built-in profiles cannot be deleted")

    db.delete(profile)
    db.commit()
    return {"status": "deleted", "profile_id": profile_id}


@router.post("/profiles/{profile_id}/set-default", response_model=ScanProfileResponse)
def set_default_profile(profile_id: str, db: Session = Depends(get_db)):
    profile = db.get(ScanProfile, profile_id)
    if not profile:
        raise HTTPException(404, "Scan profile not found")

    # Clear previous defaults
    db.query(ScanProfile).update({ScanProfile.is_default: False})
    profile.is_default = True
    db.commit()
    db.refresh(profile)
    return profile


# =============================================================================
# BUG BOUNTY PROGRAMS API
# =============================================================================

@router.get("/programs", response_model=List[ScanProgramResponse])
@router.get("/profiles/programs", response_model=List[ScanProgramResponse])
def list_programs(db: Session = Depends(get_db)):
    return db.query(ScanProgram).order_by(ScanProgram.name.asc()).all()


@router.get("/programs/{program_id}", response_model=ScanProgramResponse)
@router.get("/profiles/programs/{program_id}", response_model=ScanProgramResponse)
def get_program(program_id: str, db: Session = Depends(get_db)):
    program = db.get(ScanProgram, program_id)
    if not program:
        raise HTTPException(404, "Bug bounty program configuration not found")
    return program


@router.post("/programs", response_model=ScanProgramResponse, status_code=201)
@router.post("/profiles/programs", response_model=ScanProgramResponse, status_code=201)
def create_program(req: ScanProgramCreateRequest, db: Session = Depends(get_db)):
    existing = db.query(ScanProgram).filter(ScanProgram.name == req.name.strip()).first()
    if existing:
        raise HTTPException(409, f"A program named '{req.name.strip()}' already exists")

    program = ScanProgram(
        name=req.name.strip(),
        description=req.description,
        target_domains=req.target_domains,
        url_patterns=req.url_patterns or [],
        out_of_scope_paths=req.out_of_scope_paths or [],
        allowed_modules=req.allowed_modules or [],
        prohibited_modules=req.prohibited_modules or [],
        max_requests_per_second=req.max_requests_per_second,
        max_concurrency=req.max_concurrency,
        max_depth=req.max_depth,
        max_urls=req.max_urls,
        allow_automated_scanning=req.allow_automated_scanning if req.allow_automated_scanning is not None else True,
        auth_config=req.auth_config,
        notes=req.notes,
    )
    db.add(program)
    db.commit()
    db.refresh(program)
    return program


@router.put("/programs/{program_id}", response_model=ScanProgramResponse)
@router.put("/profiles/programs/{program_id}", response_model=ScanProgramResponse)
def update_program(program_id: str, req: ScanProgramUpdateRequest, db: Session = Depends(get_db)):
    program = db.get(ScanProgram, program_id)
    if not program:
        raise HTTPException(404, "Bug bounty program configuration not found")

    if req.name and req.name.strip() != program.name:
        existing = db.query(ScanProgram).filter(ScanProgram.name == req.name.strip(), ScanProgram.id != program_id).first()
        if existing:
            raise HTTPException(409, f"A program named '{req.name.strip()}' already exists")
        program.name = req.name.strip()

    if req.description is not None:
        program.description = req.description
    if req.target_domains is not None:
        program.target_domains = req.target_domains
    if req.url_patterns is not None:
        program.url_patterns = req.url_patterns
    if req.out_of_scope_paths is not None:
        program.out_of_scope_paths = req.out_of_scope_paths
    if req.allowed_modules is not None:
        program.allowed_modules = req.allowed_modules
    if req.prohibited_modules is not None:
        program.prohibited_modules = req.prohibited_modules
    if req.max_requests_per_second is not None:
        program.max_requests_per_second = req.max_requests_per_second
    if req.max_concurrency is not None:
        program.max_concurrency = req.max_concurrency
    if req.max_depth is not None:
        program.max_depth = req.max_depth
    if req.max_urls is not None:
        program.max_urls = req.max_urls
    if req.allow_automated_scanning is not None:
        program.allow_automated_scanning = req.allow_automated_scanning
    if req.auth_config is not None:
        program.auth_config = req.auth_config
    if req.notes is not None:
        program.notes = req.notes

    program.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(program)
    return program


@router.delete("/programs/{program_id}")
@router.delete("/profiles/programs/{program_id}")
def delete_program(program_id: str, db: Session = Depends(get_db)):
    program = db.get(ScanProgram, program_id)
    if not program:
        raise HTTPException(404, "Bug bounty program configuration not found")

    db.delete(program)
    db.commit()
    return {"status": "deleted", "program_id": program_id}
