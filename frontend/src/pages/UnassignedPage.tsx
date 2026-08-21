import PageHeader from "../components/PageHeader";

export default function UnassignedPage() {
  return (
    <div className="space-y-6 pt-fade-up">
      <PageHeader
        breadcrumbs={[{ label: "Account" }]}
        title="Organisation assignment required"
        description="This account cannot open company investigation data until an administrator assigns it."
      />
      <p className="max-w-xl text-sm text-navy-900" role="status">
        Your account is not currently assigned to an organisation. Contact an organisation
        administrator or accept an invitation.
      </p>
    </div>
  );
}
