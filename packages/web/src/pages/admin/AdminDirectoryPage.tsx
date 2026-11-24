import { useEffect, useState } from "react";
import type { DirectoryDiagnosis, DirectoryEmailAttribute } from "@sbom/shared";
import { useDirectoryGroups, useDirectorySettings, useSaveDirectoryConnection, useTestDirectoryConnection } from "../../lib/directory.ts";
import { useSetModuleEnabled } from "../../lib/mutations.ts";
import { useDebounced } from "../../lib/useDebounced.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Checkbox,
  ErrorBanner,
  FormError,
  FormRow,
  LoadingBlock,
  Mono,
  PageHeader,
  Select,
  Textarea,
  TextInput,
} from "../../components/ui.tsx";

/**
 * Administration > Directory: the organisation's Active Directory, read so squad membership can
 * follow it. Read only: the platform searches, it never writes to the directory.
 *
 * Set up and tested here while the module is off; switched on here once the test passes.
 */
export function AdminDirectoryPage() {
  const settings = useDirectorySettings();
  return (
    <div className="space-y-4">
      <PageHeader
        title="Directory"
        subtitle="Connect your Active Directory so squads can follow its groups. Sign-in stays single sign-on."
      />
      {settings.isLoading ? (
        <LoadingBlock />
      ) : settings.error ? (
        <ErrorBanner error={settings.error} onRetry={() => void settings.refetch()} />
      ) : (
        <>
          <ConnectionCard />
          <SwitchCard />
          {settings.data?.connection ? <GroupSearchCard /> : null}
        </>
      )}
    </div>
  );
}

function ConnectionCard() {
  const settings = useDirectorySettings();
  const save = useSaveDirectoryConnection();
  const test = useTestDirectoryConnection();
  const stored = settings.data?.connection ?? null;

  const [servers, setServers] = useState("");
  const [port, setPort] = useState("636");
  const [baseDn, setBaseDn] = useState("");
  const [bindUser, setBindUser] = useState("");
  const [password, setPassword] = useState("");
  const [emailAttribute, setEmailAttribute] = useState<DirectoryEmailAttribute>("mail");
  const [caCertificate, setCaCertificate] = useState("");

  // Seeded when the stored connection arrives or changes, never on every render.
  useEffect(() => {
    if (!stored) return;
    setServers(stored.servers.join(", "));
    setPort(String(stored.port));
    setBaseDn(stored.baseDn);
    setBindUser(stored.bindUser);
    setEmailAttribute(stored.emailAttribute);
    setCaCertificate(stored.caCertificate ?? "");
  }, [stored]);

  const serverList = servers.split(/[\s,;]+/).map((s) => s.trim()).filter((s) => s !== "");
  const passwordAvailable = password !== "" || (stored?.passwordConfigured ?? false);
  const complete = serverList.length > 0 && baseDn.trim() !== "" && bindUser.trim() !== "" && passwordAvailable && /^\d+$/.test(port);
  const changed =
    stored === null
      ? serverList.length > 0 || baseDn.trim() !== "" || bindUser.trim() !== "" || password !== ""
      : serverList.join(",") !== stored.servers.join(",") ||
        Number(port) !== stored.port ||
        baseDn.trim() !== stored.baseDn ||
        bindUser.trim() !== stored.bindUser ||
        password !== "" ||
        emailAttribute !== stored.emailAttribute ||
        caCertificate.trim() !== (stored.caCertificate ?? "");

  async function onSave() {
    await save.mutateAsync({
      type: "ldap",
      preset: "active-directory",
      servers: serverList,
      port: Number(port),
      baseDn: baseDn.trim(),
      bindUser: bindUser.trim(),
      ...(password === "" ? {} : { bindPassword: password }),
      emailAttribute,
      caCertificate: caCertificate.trim(),
    });
    // Cleared only after the save succeeded, so a rejected save keeps what was typed.
    setPassword("");
  }

  const verdict = test.data ?? settings.data?.lastTest ?? null;

  return (
    <Card>
      <CardHeader
        title="Active Directory connection"
        subtitle="LDAPS only (encrypted). A read-only service account is enough: the platform never changes anything in the directory."
      />
      <div className="space-y-4 p-4 pt-0">
        <div className="grid gap-4 sm:grid-cols-[1fr_120px]">
          <FormRow
            label="Domain controllers"
            htmlFor="dir-servers"
            hint="Host names, comma-separated, tried in order: the first that answers is used. Use the names on their certificates."
          >
            <TextInput id="dir-servers" value={servers} onChange={setServers} placeholder="dc1.corp.example, dc2.corp.example" />
          </FormRow>
          <FormRow label="Port" htmlFor="dir-port" hint="LDAPS: 636">
            <TextInput id="dir-port" value={port} onChange={setPort} />
          </FormRow>
        </div>

        <FormRow label="Base DN" htmlFor="dir-base" hint="Where people and groups are searched: your domain, or an OU in it.">
          <TextInput id="dir-base" value={baseDn} onChange={setBaseDn} placeholder="DC=corp,DC=example" />
        </FormRow>

        <div className="grid gap-4 sm:grid-cols-2">
          <FormRow label="Service account" htmlFor="dir-user" hint="user@domain, DOMAIN\name or its DN. Read rights are enough.">
            <TextInput id="dir-user" value={bindUser} onChange={setBindUser} placeholder="svc-sbom@corp.example" autoComplete="off" />
          </FormRow>
          <FormRow
            label="Password"
            htmlFor="dir-password"
            hint={
              stored?.passwordConfigured
                ? "A password is stored. Leave this blank to keep it; it is never shown again."
                : "Stored encrypted. Ask for one that does not expire, or the sync stops when it does."
            }
          >
            <TextInput
              id="dir-password"
              type="password"
              value={password}
              onChange={setPassword}
              autoComplete="new-password"
              placeholder={stored?.passwordConfigured ? "•••••••• (stored)" : ""}
            />
          </FormRow>
        </div>

        <FormRow
          label="Email address in the directory"
          htmlFor="dir-email"
          hint="How a person here is matched to AD: the address single sign-on gives must be the one in this attribute."
        >
          <Select
            id="dir-email"
            value={emailAttribute}
            onChange={setEmailAttribute}
            options={[
              { value: "mail", label: "mail (the email address - usual)" },
              { value: "userPrincipalName", label: "userPrincipalName (the sign-in name)" },
            ]}
          />
        </FormRow>

        <FormRow
          label="CA certificate (optional)"
          htmlFor="dir-ca"
          hint="The certificates in the installation's ca folder are trusted already - your organisation's root usually belongs there. Paste one here only if it is not."
        >
          <Textarea id="dir-ca" value={caCertificate} onChange={setCaCertificate} rows={3} placeholder="-----BEGIN CERTIFICATE-----" />
        </FormRow>

        <FormError error={save.error} />

        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary" disabled={!complete || !changed || save.isPending} onClick={() => void onSave()}>
            {save.isPending ? "Saving…" : "Save connection"}
          </Button>
          <Button disabled={stored === null || changed || test.isPending} onClick={() => void test.mutateAsync()}>
            {test.isPending ? "Testing…" : "Test connection"}
          </Button>
          {changed && stored !== null ? <span className="text-xs text-text-faint">Save first: the test uses the saved connection.</span> : null}
        </div>

        {verdict ? <Verdict verdict={verdict} /> : null}
      </div>
    </Card>
  );
}

function Verdict({ verdict }: { verdict: DirectoryDiagnosis }) {
  return (
    <div className="space-y-1 rounded-md border border-border-base p-3">
      <div className="flex items-center gap-2">
        <Badge tone={verdict.ok ? "ok" : "danger"}>{verdict.ok ? "Working" : "Failed"}</Badge>
        <span className="text-xs text-text-muted">{verdict.code}</span>
        <span className="text-xs text-text-faint">{new Date(verdict.at).toLocaleString()}</span>
      </div>
      <p className="text-sm text-text-base">{verdict.summary}</p>
      {verdict.hint ? <p className="text-xs text-text-muted">{verdict.hint}</p> : null}
      {verdict.detail ? (
        <p className="text-xs text-text-faint">
          <Mono>{verdict.detail}</Mono>
        </p>
      ) : null}
    </div>
  );
}

function SwitchCard() {
  const settings = useDirectorySettings();
  const setEnabled = useSetModuleEnabled();
  const enabled = settings.data?.enabled ?? false;
  const configured = settings.data?.connection !== null && settings.data?.connection !== undefined;
  return (
    <Card>
      <CardHeader
        title="Use the directory"
        subtitle="Off until you switch it on. Off, nothing reads the directory and squads stay exactly as they are."
      />
      <div className="space-y-2 p-4 pt-0">
        <Checkbox
          checked={enabled}
          disabled={!configured || setEnabled.isPending}
          onChange={(on) => void setEnabled.mutateAsync({ id: "directory", enabled: on })}
          label="Directory module on"
        />
        {!configured ? <p className="text-xs text-text-faint">Save a connection first.</p> : null}
        <FormError error={setEnabled.error} />
      </div>
    </Card>
  );
}

/** Shows that the platform sees the directory's groups; squads will be linked to them. */
function GroupSearchCard() {
  const [q, setQ] = useState("");
  const term = useDebounced(q, 300);
  const groups = useDirectoryGroups(term);
  return (
    <Card>
      <CardHeader title="Find a group" subtitle="Search the directory's groups by name, to check what the platform can see." />
      <div className="space-y-3 p-4 pt-0">
        <TextInput value={q} onChange={setQ} placeholder="At least two letters, e.g. Squad" ariaLabel="Search directory groups" />
        {term.trim().length < 2 ? null : groups.isLoading ? (
          <LoadingBlock />
        ) : groups.error ? (
          <ErrorBanner error={groups.error} onRetry={() => void groups.refetch()} />
        ) : (groups.data ?? []).length === 0 ? (
          <p className="text-sm text-text-muted">No group's name contains “{term.trim()}”.</p>
        ) : (
          <ul className="divide-y divide-border-base rounded-md border border-border-base">
            {groups.data!.map((g) => (
              <li key={g.id} className="px-3 py-2">
                <div className="text-sm font-medium text-text-base">{g.name}</div>
                <div className="text-xs break-all text-text-faint">
                  <Mono>{g.dn}</Mono>
                </div>
                {g.description ? <div className="text-xs text-text-muted">{g.description}</div> : null}
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
