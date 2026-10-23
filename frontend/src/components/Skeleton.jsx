// Shimmering placeholder bars shown while data loads (styles: .skeleton in theme.css).
const WIDTHS = ["92%", "78%", "85%", "64%", "88%", "70%"];

export function Skeleton({ lines = 3 }) {
  return (
    <div className="space-y-2 py-1" aria-busy="true" aria-label="Loading">
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} className="skeleton" style={{ width: WIDTHS[i % WIDTHS.length] }} />
      ))}
    </div>
  );
}

// Full-page placeholder: a title bar, three tiles and a panel.
export function PageSkeleton() {
  return (
    <div aria-busy="true" aria-label="Loading">
      <span className="skeleton mb-5" style={{ width: "12rem", height: "1.5rem" }} />
      <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        {[0, 1, 2].map((i) => (
          <div key={i} className="glass rounded border p-4">
            <Skeleton lines={2} />
          </div>
        ))}
      </div>
      <div className="glass rounded border p-4">
        <Skeleton lines={5} />
      </div>
    </div>
  );
}
