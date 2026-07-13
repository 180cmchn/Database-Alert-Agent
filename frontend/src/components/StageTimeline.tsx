import { Check, Circle, CircleAlert, LoaderCircle } from "lucide-react";
import { stageLabel } from "../lib/format";
import type { InvestigationStage, ProgressRecord } from "../types/api";

const CORE_STAGES: InvestigationStage[] = [
  "RECEIVED",
  "FINGERPRINTING",
  "KNOWLEDGE_MATCHING",
  "RUNBOOK_MATCHING",
  "INVESTIGATING",
  "ADVISING",
  "VALIDATING",
  "REPORTING",
];

const finalStages: InvestigationStage[] = ["COMPLETED", "REVIEW_REQUIRED", "FAILED"];

export function StageTimeline({
  currentStage,
  progress,
}: {
  currentStage?: InvestigationStage | null;
  progress: ProgressRecord[];
}) {
  const progressByStage = new Map<InvestigationStage, ProgressRecord>();
  [...progress]
    .sort((a, b) => a.sequence - b.sequence)
    .forEach((record) => progressByStage.set(record.stage, record));

  const currentIndex = currentStage ? CORE_STAGES.indexOf(currentStage) : -1;
  const terminal = currentStage && finalStages.includes(currentStage) ? currentStage : undefined;
  const stages = terminal ? [...CORE_STAGES, terminal] : CORE_STAGES;

  return (
    <ol className="stage-timeline">
      {stages.map((stage, index) => {
        const record = progressByStage.get(stage);
        const isTerminal = finalStages.includes(stage);
        const isFailed = stage === "FAILED" || stage === "REVIEW_REQUIRED";
        const isCurrent = stage === currentStage;
        const isDone = Boolean(record) || isTerminal || (currentIndex >= 0 && index < currentIndex);
        const Icon = isFailed
          ? CircleAlert
          : isCurrent && !isTerminal
            ? LoaderCircle
            : isDone
              ? Check
              : Circle;

        return (
          <li
            key={`${stage}-${index}`}
            className={`${isDone ? "done" : "pending"} ${isCurrent ? "current" : ""} ${isFailed ? "failed" : ""}`}
          >
            <span className="stage-rail" aria-hidden="true" />
            <span className="stage-icon">
              <Icon size={15} className={isCurrent && !isTerminal ? "spin" : ""} />
            </span>
            <div>
              <strong>{stageLabel[stage]}</strong>
              <p>{record?.message || (isCurrent ? "Agent 正在执行此步骤" : "等待前序步骤完成")}</p>
              {record && <time dateTime={record.created_at}>{new Date(record.created_at).toLocaleTimeString("zh-CN", { hour12: false })}</time>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
