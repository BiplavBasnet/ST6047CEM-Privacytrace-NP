import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import ConfirmDialog from "../components/ConfirmDialog";
import DetailInspector from "../components/DetailInspector";
import { SegmentedTabs } from "../components/ui/primitives";

describe("console primitives", () => {
  it("opens a native confirm dialog and confirms", () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(
      <ConfirmDialog
        open
        title="Revoke token"
        body="This cannot be undone."
        confirmLabel="Revoke"
        danger
        onConfirm={onConfirm}
        onCancel={onCancel}
      />,
    );
    expect(screen.getByRole("heading", { name: "Revoke token" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("renders an inspector pane", () => {
    render(
      <DetailInspector title="Alert detail">
        <p>Selected alert</p>
      </DetailInspector>,
    );
    expect(screen.getByRole("heading", { name: "Alert detail" })).toBeInTheDocument();
    expect(screen.getByText("Selected alert")).toBeInTheDocument();
  });

  it("switches segmented tabs", () => {
    const onChange = vi.fn();
    render(
      <SegmentedTabs
        tabs={[
          { id: "a", label: "Overview" },
          { id: "b", label: "Tokens" },
        ]}
        value="a"
        onChange={onChange}
      />,
    );
    fireEvent.click(screen.getByRole("tab", { name: "Tokens" }));
    expect(onChange).toHaveBeenCalledWith("b");
  });
});
