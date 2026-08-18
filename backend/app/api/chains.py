from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.chain import AttackStage, ChainDetail, ChainEdgeRead, ChainNodeRead, ChainSummary
from app.schemas.event import EventRead
from app.services.chains import get_chain, query_chains

router = APIRouter(prefix="/api/chains", tags=["attack chains"])
DatabaseSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[ChainSummary])
def list_chains(
    db: DatabaseSession,
    stage: Annotated[AttackStage | None, Query()] = None,
    min_confidence: Annotated[int | None, Query(ge=0, le=100)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ChainSummary]:
    records = query_chains(
        db,
        stage=stage.value if stage else None,
        min_confidence=min_confidence,
        limit=limit,
        offset=offset,
    )
    return [ChainSummary.model_validate(record) for record in records]


@router.get("/{chain_id}", response_model=ChainDetail)
def read_chain(chain_id: UUID, db: DatabaseSession) -> ChainDetail:
    result = get_chain(db, chain_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="attack chain not found")
    chain, nodes, edges, events = result
    summary = ChainSummary.model_validate(chain)
    return ChainDetail(
        **summary.model_dump(),
        nodes=[ChainNodeRead.model_validate(node) for node in nodes],
        edges=[ChainEdgeRead.model_validate(edge) for edge in edges],
        events=[EventRead.model_validate(event) for event in events],
    )
