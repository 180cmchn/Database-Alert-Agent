import { ArrowLeft, Radar } from "lucide-react";
import { Link } from "react-router-dom";

export function NotFoundPage() {
  return (
    <section className="not-found-page">
      <span><Radar size={36} /></span>
      <p className="eyebrow">404 · SIGNAL LOST</p>
      <h1>没有找到这个页面</h1>
      <p>链接可能已经失效，或对应的控制台功能尚未启用。</p>
      <Link className="button primary" to="/"><ArrowLeft size={16} /> 返回态势总览</Link>
    </section>
  );
}
