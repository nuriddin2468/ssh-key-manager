import { Bot, ChevronDown } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { AgentRules } from '@/bindings/AgentRules';
import type { AgentRulesView } from '@/bindings/AgentRulesView';
import type { AgentTool } from '@/bindings/AgentTool';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { refreshFileReports } from './queries';

/** The tools' own names, as they call themselves. */
export const AGENT_NAMES: Record<AgentTool, string> = {
  claudeCode: 'Claude Code',
  cursor: 'Cursor',
  windsurf: 'Windsurf',
  aider: 'Aider',
  geminiCli: 'Gemini CLI',
  cline: 'Cline',
  rooCode: 'Roo Code',
  continue: 'Continue',
  jetBrains: 'JetBrains AI, Gemini Code Assist',
};

/** Lines shown for a tool before "and N more". */
const SHOWN_LINES = 3;

/** A tool whose file lacks lines and can be changed. */
export const needsRules = (rules: AgentRules) => rules.problem === null && rules.missing.length > 0;

/** The tools used here whose files lack lines: the ones the app offers. */
export const offered = (view: AgentRulesView) =>
  view.tools.filter((rules) => rules.found && needsRules(rules));

interface AgentRulesDialogProps {
  project: string;
  view: AgentRulesView;
  onDone: () => void;
}

/**
 * Asks before adding a project folder's managed `.env` files to AI tools'
 * own ignore files: each tool, its file and the exact lines, the tools used
 * on this computer chosen at first. Saying no is remembered for the folder.
 */
export function AgentRulesDialog({ project, view, onDone }: AgentRulesDialogProps) {
  const { t } = useTranslation();
  const [chosen, setChosen] = useState<Set<AgentTool>>(
    () => new Set(offered(view).map((rules) => rules.tool)),
  );
  const add = useVaultMutation(
    (tools: AgentTool[]) => api.envsAgentsAdd(project, view.folder, tools),
    {
      success: (_, tools) =>
        t('envs.agents.added', {
          count: tools.length,
          tools: tools.map((tool) => AGENT_NAMES[tool]).join(', '),
        }),
      onSuccess: () => {
        void refreshFileReports();
        onDone();
      },
    },
  );
  const decline = useVaultMutation(() => api.envsAgentsDecline(project, view.folder), {
    success: () => t('envs.agents.declined', { folder: view.folder }),
    onSuccess: () => {
      void refreshFileReports();
      onDone();
    },
  });
  const toggle = (tool: AgentTool, on: boolean) =>
    setChosen((now) => {
      const next = new Set(now);
      if (on) next.add(tool);
      else next.delete(tool);
      return next;
    });
  const busy = add.isPending || decline.isPending;
  const used = view.tools.filter((rules) => rules.found);
  const others = view.tools.filter((rules) => !rules.found);
  // The tools not seen here wait behind a button, unless none is seen.
  const [showOthers, setShowOthers] = useState(used.length === 0);
  const tools = showOthers ? [...used, ...others] : used;
  return (
    <DialogContent section="envs" className="max-w-[600px]">
      <DialogHeader
        icon={
          <Tile tone="violet" size={44} glow>
            <Bot className="size-[22px]" strokeWidth={2} />
          </Tile>
        }
        title={t('envs.agents.title')}
        description={t('envs.agents.description', { folder: view.folder })}
      />
      <DialogBody>
        <ul aria-label={t('envs.agents.listLabel')} className="flex flex-col gap-2">
          {tools.map((rules) => (
            <ToolRow
              key={rules.tool}
              rules={rules}
              checked={chosen.has(rules.tool)}
              disabled={busy}
              onChange={(on) => toggle(rules.tool, on)}
            />
          ))}
        </ul>
        {others.length > 0 && used.length > 0 ? (
          <Button
            variant="ghost"
            size="sm"
            className="self-start"
            aria-expanded={showOthers}
            icon={
              <ChevronDown
                className={showOthers ? 'size-3.5 rotate-180' : 'size-3.5'}
                strokeWidth={2.2}
              />
            }
            onClick={() => setShowOthers((now) => !now)}
          >
            {showOthers
              ? t('envs.agents.fewerTools')
              : t('envs.agents.otherTools', { count: others.length })}
          </Button>
        ) : null}
        <p className="text-[12px] leading-[17px] text-subtle">{t('envs.agents.later')}</p>
      </DialogBody>
      <DialogFooter>
        {view.choice === null ? (
          <Button
            size="lg"
            variant="ghost"
            className="mr-auto"
            loading={decline.isPending}
            disabled={busy}
            onClick={() => decline.mutate(undefined)}
          >
            {t('envs.agents.notHere')}
          </Button>
        ) : null}
        <Button size="lg" disabled={busy} onClick={onDone}>
          {t('common.cancel')}
        </Button>
        <Button
          size="lg"
          variant="primary"
          loading={add.isPending}
          disabled={busy || chosen.size === 0}
          onClick={() => add.mutate([...chosen])}
        >
          {t('envs.agents.add')}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

interface ToolRowProps {
  rules: AgentRules;
  checked: boolean;
  disabled: boolean;
  onChange: (on: boolean) => void;
}

/** One tool: its file, what it lacks, or why it can't be changed. */
function ToolRow({ rules, checked, disabled, onChange }: ToolRowProps) {
  const { t } = useTranslation();
  const can = needsRules(rules);
  const shown = rules.missing.slice(0, SHOWN_LINES);
  const more = rules.missing.length - shown.length;
  const state = rules.problem
    ? t(`envs.agents.problem.${rules.problem}`)
    : rules.missing.length === 0
      ? t('envs.agents.covered')
      : rules.exists
        ? t('envs.agents.adds', { count: rules.missing.length })
        : t('envs.agents.makes');
  return (
    <li className="rounded-xl border border-white/[0.07] bg-white/[0.025] px-3 py-2">
      <Checkbox
        checked={can && checked}
        disabled={disabled || !can}
        onCheckedChange={onChange}
        label={
          <span className="flex flex-col gap-0.5">
            <span className="flex flex-wrap items-baseline gap-x-2">
              <span>{AGENT_NAMES[rules.tool]}</span>
              <span className="font-mono text-[11.5px] font-normal text-subtle">{rules.file}</span>
            </span>
            <span className="text-[12px] font-normal text-muted">
              {state}
              {rules.found ? null : ` · ${t('envs.agents.notFound')}`}
            </span>
            {can ? (
              <span className="selectable font-mono text-[11.5px] font-normal break-all text-fg-2">
                {shown.join('  ')}
                {more > 0 ? ` ${t('envs.agents.more', { count: more })}` : null}
              </span>
            ) : null}
          </span>
        }
      />
    </li>
  );
}
