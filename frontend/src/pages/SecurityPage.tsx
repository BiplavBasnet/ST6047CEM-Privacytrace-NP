import { useEffect, useState } from "react";
import { api, type SecurityProfile } from "../api/client";
import PageHeader from "../components/PageHeader";
import { ErrorState, LoadingState } from "../components/LoadingError";
import { sanitizeString } from "../utils/safety";

export default function SecurityPage() {
  const [profile, setProfile] = useState<SecurityProfile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void (async () => {
      try {
        const data = await api.getSecurityProfile();
        setProfile(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load security profile");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) return <LoadingState message="Loading security profile…" />;
  if (error) return <ErrorState message={error} />;
  if (!profile) return <ErrorState message="No profile data" />;

  return (
    <div className="space-y-4">
      <PageHeader
        breadcrumbs={[
          { label: "Dashboard", to: "/" },
          { label: "Security Profile" },
        ]}
        title="Security Profile"
        description="Active cryptographic and NIST-aligned configuration for this deployment."
      />
      <p className="body-muted">{sanitizeString(profile.compliance_note)}</p>
      <dl className="grid gap-3 text-sm sm:grid-cols-2">
        <Item label="Encryption enabled" value={profile.crypto_mode_enabled ? "yes" : "no"} />
        <Item label="Symmetric" value={profile.symmetric_algorithm} />
        <Item label="Key wrap" value={profile.key_wrap_algorithm} />
        <Item label="JWT signing" value={profile.jwt_signing} />
        <Item label="Asymmetric JWT" value={profile.jwt_asymmetric_enabled ? "yes" : "no"} />
        <Item label="Password hashing" value={profile.password_hash_algorithm} />
        <Item label="Active key id" value={profile.active_key_id} />
        <Item label="NIST CSF 2.0 functions" value={profile.nist_csf_functions.join(" · ")} />
        <Item label="Referenced SP 800 documents" value={profile.nist_sp_documents_referenced.join(", ")} />
      </dl>
      <p className="body-muted text-xs">{sanitizeString(profile.fips_aware_note)}</p>
    </div>
  );
}

function Item({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-ink-subtle">{label}</dt>
      <dd className="mt-1 text-navy-900">{sanitizeString(value)}</dd>
    </div>
  );
}
