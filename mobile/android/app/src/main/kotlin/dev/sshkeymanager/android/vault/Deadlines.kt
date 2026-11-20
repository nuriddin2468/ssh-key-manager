package dev.sshkeymanager.android.vault

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import dev.sshkeymanager.android.SshkmApplication

/** Something that must happen even if the app is in the background by then. */
enum class Deadline(val jobId: Int) {
    /** Lock the vault after [LockAfter] without use. */
    LOCK(1),

    /** Clear a copied password or code. */
    CLEAR_CLIPBOARD(2),
    ;

    companion object {
        fun of(jobId: Int): Deadline? = entries.firstOrNull { it.jobId == jobId }
    }
}

/** Runs a [Deadline] later; tests stand in for it. */
interface Deadlines {
    fun schedule(deadline: Deadline, delayMillis: Long)

    fun cancel(deadline: Deadline)
}

/**
 * Deadlines through JobScheduler. Android freezes an app soon after it
 * leaves the screen, so its own timers stop; a job thaws it (or starts it
 * again) to lock the vault or clear the clipboard. While the app is on
 * screen its own timers get there first.
 */
class JobDeadlines(private val context: Context) : Deadlines {
    private val scheduler: JobScheduler? = context.getSystemService(JobScheduler::class.java)

    override fun schedule(deadline: Deadline, delayMillis: Long) {
        val job =
            JobInfo
                .Builder(deadline.jobId, ComponentName(context, DeadlineJobService::class.java))
                .setMinimumLatency(delayMillis.coerceAtLeast(0))
                .build()
        scheduler?.schedule(job)
    }

    override fun cancel(deadline: Deadline) {
        scheduler?.cancel(deadline.jobId)
    }
}

/** Runs a [Deadline] when JobScheduler says it's time; the job lasts until the vault is locked in the core. */
class DeadlineJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        val deadline = Deadline.of(params.jobId) ?: return false
        val work = (application as SshkmApplication).graph.onDeadline(deadline) ?: return false
        work.invokeOnCompletion { jobFinished(params, false) }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = false
}
