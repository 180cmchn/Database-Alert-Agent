import { Check, CirclePlus, Pencil, Trash2, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { formatDateTime } from "../lib/format";
import type {
  WeComMentionEngineOwner,
  WeComMentionFlashDutyMember,
  WeComMentionTarget,
} from "../types/api";
import { ConfirmDialog, InlineLoading } from "./ui";

interface TargetDraft {
  display_label: string;
  wecom_userid: string;
  wecom_mobile: string;
}

const EMPTY_TARGET_DRAFT: TargetDraft = { display_label: "", wecom_userid: "", wecom_mobile: "" };

function targetToDraft(target: WeComMentionTarget): TargetDraft {
  return {
    display_label: target.display_label,
    wecom_userid: target.wecom_userid || "",
    wecom_mobile: target.wecom_mobile || "",
  };
}

function draftToTarget(draft: TargetDraft): WeComMentionTarget | null {
  const display_label = draft.display_label.trim();
  const wecom_userid = draft.wecom_userid.trim();
  const wecom_mobile = draft.wecom_mobile.trim();
  if (!display_label || (!wecom_userid && !wecom_mobile)) return null;
  return { display_label, wecom_userid: wecom_userid || null, wecom_mobile: wecom_mobile || null };
}

function TargetFieldsInline({
  draft,
  onChange,
  disabled,
}: {
  draft: TargetDraft;
  onChange: (draft: TargetDraft) => void;
  disabled?: boolean;
}) {
  return (
    <div className="mention-target-fields">
      <input
        placeholder="展示名称（如 张三 / MySQL 值班组）"
        value={draft.display_label}
        disabled={disabled}
        onChange={(event) => onChange({ ...draft, display_label: event.target.value })}
      />
      <input
        placeholder="企微 userid（优先）"
        value={draft.wecom_userid}
        disabled={disabled}
        onChange={(event) => onChange({ ...draft, wecom_userid: event.target.value })}
      />
      <input
        placeholder="手机号（无 userid 时使用）"
        value={draft.wecom_mobile}
        disabled={disabled}
        onChange={(event) => onChange({ ...draft, wecom_mobile: event.target.value })}
      />
    </div>
  );
}

export function WeComMentionEngineOwnersEditor({ token }: { token: string }) {
  const [items, setItems] = useState<WeComMentionEngineOwner[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [editingEngine, setEditingEngine] = useState<string | null>(null);
  const [editDraft, setEditDraft] = useState<TargetDraft>(EMPTY_TARGET_DRAFT);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newEngine, setNewEngine] = useState("");
  const [newDraft, setNewDraft] = useState<TargetDraft>(EMPTY_TARGET_DRAFT);
  const [rowError, setRowError] = useState("");
  const [confirmDeleteEngine, setConfirmDeleteEngine] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await api.getWeComMentionEngineOwners(token);
      setItems([...response.items].sort((a, b) => a.engine.localeCompare(b.engine)));
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "映射列表加载失败");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { void load(); }, [load]);

  function startEdit(owner: WeComMentionEngineOwner) {
    setEditingEngine(owner.engine);
    setEditDraft(targetToDraft(owner.target));
    setRowError("");
  }

  async function saveEdit(engine: string) {
    const target = draftToTarget(editDraft);
    if (!target) {
      setRowError("请填写展示名称，并至少提供企微 userid 或手机号之一。");
      return;
    }
    setBusyKey(engine);
    setRowError("");
    try {
      await api.upsertWeComMentionEngineOwner(engine, target, token);
      setEditingEngine(null);
      await load();
    } catch (saveError) {
      setRowError(saveError instanceof Error ? saveError.message : "保存失败");
    } finally {
      setBusyKey(null);
    }
  }

  async function submitNew() {
    const engine = newEngine.trim();
    const target = draftToTarget(newDraft);
    if (!engine) {
      setRowError("请填写数据库类型（engine）标识。");
      return;
    }
    if (!target) {
      setRowError("请填写展示名称，并至少提供企微 userid 或手机号之一。");
      return;
    }
    setBusyKey("__new__");
    setRowError("");
    try {
      await api.upsertWeComMentionEngineOwner(engine, target, token);
      setShowAddForm(false);
      setNewEngine("");
      setNewDraft(EMPTY_TARGET_DRAFT);
      await load();
    } catch (submitError) {
      setRowError(submitError instanceof Error ? submitError.message : "新增失败");
    } finally {
      setBusyKey(null);
    }
  }

  async function confirmDelete() {
    if (!confirmDeleteEngine) return;
    setBusyKey(confirmDeleteEngine);
    try {
      await api.deleteWeComMentionEngineOwner(confirmDeleteEngine, token);
      setConfirmDeleteEngine(null);
      await load();
    } catch (deleteError) {
      setError(deleteError instanceof Error ? deleteError.message : "删除失败");
      setConfirmDeleteEngine(null);
    } finally {
      setBusyKey(null);
    }
  }

  if (loading) return <InlineLoading label="正在读取数据库类型映射…" />;

  return (
    <div className="mention-mapping-block">
      {error && <div className="form-error" role="alert">{error}</div>}
      <div className="alert-table-wrap">
        <table className="alert-table">
          <thead>
            <tr>
              <th>数据库类型</th>
              <th>展示名称</th>
              <th>企微 userid</th>
              <th>手机号</th>
              <th>更新时间 / 更新人</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {items.map((owner) => {
              const isEditing = editingEngine === owner.engine;
              const isBusy = busyKey === owner.engine;
              return (
                <tr key={owner.engine}>
                  <td><code>{owner.engine}</code></td>
                  {isEditing ? (
                    <td colSpan={3}>
                      <TargetFieldsInline draft={editDraft} onChange={setEditDraft} disabled={isBusy} />
                    </td>
                  ) : (
                    <>
                      <td>{owner.target.display_label}</td>
                      <td>{owner.target.wecom_userid || "—"}</td>
                      <td>{owner.target.wecom_mobile || "—"}</td>
                    </>
                  )}
                  <td><small>{formatDateTime(owner.updated_at)}{owner.updated_by ? ` · ${owner.updated_by}` : ""}</small></td>
                  <td>
                    {isEditing ? (
                      <div className="mention-row-actions">
                        <button type="button" className="button primary small" onClick={() => void saveEdit(owner.engine)} disabled={isBusy}>
                          {isBusy ? <InlineLoading label="保存中" /> : <><Check size={14} /> 保存</>}
                        </button>
                        <button type="button" className="button secondary small" onClick={() => { setEditingEngine(null); setRowError(""); }} disabled={isBusy}>
                          <X size={14} /> 取消
                        </button>
                      </div>
                    ) : (
                      <div className="mention-row-actions">
                        <button type="button" className="button secondary small" onClick={() => startEdit(owner)}>
                          <Pencil size={14} /> 编辑
                        </button>
                        <button type="button" className="button danger small" onClick={() => setConfirmDeleteEngine(owner.engine)}>
                          <Trash2 size={14} /> 删除
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
            {items.length === 0 && !showAddForm && (
              <tr><td colSpan={6}><span className="muted-copy">尚未配置任何数据库类型的负责人映射</span></td></tr>
            )}
            {showAddForm && (
              <tr>
                <td>
                  <input
                    placeholder="如 mysql / postgresql / mongodb"
                    value={newEngine}
                    onChange={(event) => setNewEngine(event.target.value)}
                    disabled={busyKey === "__new__"}
                  />
                </td>
                <td colSpan={3}>
                  <TargetFieldsInline draft={newDraft} onChange={setNewDraft} disabled={busyKey === "__new__"} />
                </td>
                <td>—</td>
                <td>
                  <div className="mention-row-actions">
                    <button type="button" className="button primary small" onClick={() => void submitNew()} disabled={busyKey === "__new__"}>
                      {busyKey === "__new__" ? <InlineLoading label="新增中" /> : <><Check size={14} /> 新增</>}
                    </button>
                    <button type="button" className="button secondary small" onClick={() => { setShowAddForm(false); setRowError(""); }} disabled={busyKey === "__new__"}>
                      <X size={14} /> 取消
                    </button>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {rowError && <div className="form-error" role="alert">{rowError}</div>}
      {!showAddForm && (
        <button type="button" className="button secondary small" onClick={() => { setShowAddForm(true); setRowError(""); }}>
          <CirclePlus size={14} /> 新增数据库类型映射
        </button>
      )}
      <ConfirmDialog
        open={confirmDeleteEngine !== null}
        title="删除该数据库类型的@提醒映射？"
        description={`删除后，${confirmDeleteEngine} 类型告警的 DATABASE_OWNER 模式提醒将不再@任何人，直至重新配置。`}
        confirmLabel="确认删除"
        busy={busyKey === confirmDeleteEngine}
        onCancel={() => setConfirmDeleteEngine(null)}
        onConfirm={() => void confirmDelete()}
      />
    </div>
  );
}

export function WeComMentionFlashDutyMembersEditor({ token }: { token: string }) {
  const [items, setItems] = useState<WeComMentionFlashDutyMember[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [editingMemberName, setEditingMemberName] = useState<string | null>(null);
  const [editDraft, setEditDraft] = useState<TargetDraft>(EMPTY_TARGET_DRAFT);
  const [showAddForm, setShowAddForm] = useState(false);
  const [newMemberName, setNewMemberName] = useState("");
  const [newDraft, setNewDraft] = useState<TargetDraft>(EMPTY_TARGET_DRAFT);
  const [rowError, setRowError] = useState("");
  const [confirmDeleteMemberName, setConfirmDeleteMemberName] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await api.getWeComMentionFlashDutyMembers(token);
      setItems(
        [...response.items].sort((a, b) => a.flashduty_member_name.localeCompare(b.flashduty_member_name)),
      );
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "映射列表加载失败");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { void load(); }, [load]);

  function startEdit(member: WeComMentionFlashDutyMember) {
    setEditingMemberName(member.flashduty_member_name);
    setEditDraft(targetToDraft(member.target));
    setRowError("");
  }

  async function saveEdit(memberName: string) {
    const target = draftToTarget(editDraft);
    if (!target) {
      setRowError("请填写展示名称，并至少提供企微 userid 或手机号之一。");
      return;
    }
    setBusyKey(memberName);
    setRowError("");
    try {
      await api.upsertWeComMentionFlashDutyMember(memberName, target, token);
      setEditingMemberName(null);
      await load();
    } catch (saveError) {
      setRowError(saveError instanceof Error ? saveError.message : "保存失败");
    } finally {
      setBusyKey(null);
    }
  }

  async function submitNew() {
    const memberName = newMemberName.trim();
    const target = draftToTarget(newDraft);
    if (!memberName) {
      setRowError("请填写 FlashDuty member_name。");
      return;
    }
    if (!target) {
      setRowError("请填写展示名称，并至少提供企微 userid 或手机号之一。");
      return;
    }
    setBusyKey("__new__");
    setRowError("");
    try {
      await api.upsertWeComMentionFlashDutyMember(memberName, target, token);
      setShowAddForm(false);
      setNewMemberName("");
      setNewDraft(EMPTY_TARGET_DRAFT);
      await load();
    } catch (submitError) {
      setRowError(submitError instanceof Error ? submitError.message : "新增失败");
    } finally {
      setBusyKey(null);
    }
  }

  async function confirmDelete() {
    if (!confirmDeleteMemberName) return;
    setBusyKey(confirmDeleteMemberName);
    try {
      await api.deleteWeComMentionFlashDutyMember(confirmDeleteMemberName, token);
      setConfirmDeleteMemberName(null);
      await load();
    } catch (deleteError) {
      setError(deleteError instanceof Error ? deleteError.message : "删除失败");
      setConfirmDeleteMemberName(null);
    } finally {
      setBusyKey(null);
    }
  }

  if (loading) return <InlineLoading label="正在读取值班/认领人员映射…" />;

  return (
    <div className="mention-mapping-block">
      {error && <div className="form-error" role="alert">{error}</div>}
      <div className="alert-table-wrap">
        <table className="alert-table">
          <thead>
            <tr>
              <th>FlashDuty member_name</th>
              <th>展示名称</th>
              <th>企微 userid</th>
              <th>手机号</th>
              <th>更新时间 / 更新人</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {items.map((member) => {
              const isEditing = editingMemberName === member.flashduty_member_name;
              const isBusy = busyKey === member.flashduty_member_name;
              return (
                <tr key={member.flashduty_member_name}>
                  <td><code>{member.flashduty_member_name}</code></td>
                  {isEditing ? (
                    <td colSpan={3}>
                      <TargetFieldsInline draft={editDraft} onChange={setEditDraft} disabled={isBusy} />
                    </td>
                  ) : (
                    <>
                      <td>{member.target.display_label}</td>
                      <td>{member.target.wecom_userid || "—"}</td>
                      <td>{member.target.wecom_mobile || "—"}</td>
                    </>
                  )}
                  <td><small>{formatDateTime(member.updated_at)}{member.updated_by ? ` · ${member.updated_by}` : ""}</small></td>
                  <td>
                    {isEditing ? (
                      <div className="mention-row-actions">
                        <button type="button" className="button primary small" onClick={() => void saveEdit(member.flashduty_member_name)} disabled={isBusy}>
                          {isBusy ? <InlineLoading label="保存中" /> : <><Check size={14} /> 保存</>}
                        </button>
                        <button type="button" className="button secondary small" onClick={() => { setEditingMemberName(null); setRowError(""); }} disabled={isBusy}>
                          <X size={14} /> 取消
                        </button>
                      </div>
                    ) : (
                      <div className="mention-row-actions">
                        <button type="button" className="button secondary small" onClick={() => startEdit(member)}>
                          <Pencil size={14} /> 编辑
                        </button>
                        <button type="button" className="button danger small" onClick={() => setConfirmDeleteMemberName(member.flashduty_member_name)}>
                          <Trash2 size={14} /> 删除
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
            {items.length === 0 && !showAddForm && (
              <tr><td colSpan={6}><span className="muted-copy">尚未配置任何 FlashDuty 成员的企微身份映射</span></td></tr>
            )}
            {showAddForm && (
              <tr>
                <td>
                  <input
                    placeholder="FlashDuty member_name（如 kobeway.wei）"
                    value={newMemberName}
                    onChange={(event) => setNewMemberName(event.target.value)}
                    disabled={busyKey === "__new__"}
                  />
                </td>
                <td colSpan={3}>
                  <TargetFieldsInline draft={newDraft} onChange={setNewDraft} disabled={busyKey === "__new__"} />
                </td>
                <td>—</td>
                <td>
                  <div className="mention-row-actions">
                    <button type="button" className="button primary small" onClick={() => void submitNew()} disabled={busyKey === "__new__"}>
                      {busyKey === "__new__" ? <InlineLoading label="新增中" /> : <><Check size={14} /> 新增</>}
                    </button>
                    <button type="button" className="button secondary small" onClick={() => { setShowAddForm(false); setRowError(""); }} disabled={busyKey === "__new__"}>
                      <X size={14} /> 取消
                    </button>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {rowError && <div className="form-error" role="alert">{rowError}</div>}
      {!showAddForm && (
        <button type="button" className="button secondary small" onClick={() => { setShowAddForm(true); setRowError(""); }}>
          <CirclePlus size={14} /> 新增值班/认领人员映射
        </button>
      )}
      <ConfirmDialog
        open={confirmDeleteMemberName !== null}
        title="删除该成员的@提醒映射？"
        description={`删除后，成员 ${confirmDeleteMemberName} 在 ON_CALL_PERSON 模式下将不再被@，直至重新配置。`}
        confirmLabel="确认删除"
        busy={busyKey === confirmDeleteMemberName}
        onCancel={() => setConfirmDeleteMemberName(null)}
        onConfirm={() => void confirmDelete()}
      />
    </div>
  );
}
