import { Component } from "react";

export default class ErrorBoundary extends Component {
  state = { error: null };

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error("Page crashed:", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="rounded border border-red-900 bg-red-950/40 p-4 text-sm text-red-300">
          Something went wrong rendering this page. Try navigating elsewhere and back.
        </div>
      );
    }
    return this.props.children;
  }
}
