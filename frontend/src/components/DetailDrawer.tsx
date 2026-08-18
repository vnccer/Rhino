import { X } from "lucide-react";
import { useEffect } from "react";

export function DetailDrawer({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="drawer-layer" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
        <header>
          <div><p className="eyebrow">INVESTIGATION DETAIL</p><h2 id="drawer-title">{title}</h2></div>
          <button className="icon-button" onClick={onClose} aria-label="关闭详情" title="关闭详情"><X size={19} /></button>
        </header>
        <div className="drawer-body">{children}</div>
      </aside>
    </div>
  );
}
