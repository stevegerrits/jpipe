import spock.lang.Specification
import io.stenic.jpipe.event.Event
import io.stenic.jpipe.plugin.TrivyPlugin

class TrivyPluginSpec extends Specification {

    // Minimal stand-in for the pipeline script. Records sh invocations and
    // simulates the shared tmp workspace via an in-memory file map, so two
    // plugin instances in the same "build" can see each other's markers.
    static class FakeScript {
        List shCommands = []
        Map files = [:]
        List published = []
        List printed = []
        List catchErrors = []
        Map env = [BUILD_TAG: 'jenkins-job-42', JOB_BASE_NAME: 'myjob']
        String imageId = 'sha256:abc123'
        boolean inspectFails = false
        // trivy exit code the scan reports: 0 = clean, 2 = vulnerabilities
        // found, any other non-zero = operational error (e.g. cache DB lock).
        int scanExitCode = 0

        def sh(def arg) {
            if (arg instanceof Map) {
                String s = arg.script.toString()
                shCommands << s
                if (s.contains('docker inspect')) {
                    if (inspectFails) {
                        throw new RuntimeException('no such image')
                    }
                    return imageId + '\n'
                }
                if (s.contains('aquasecurity/trivy')) {
                    // Scan runs with returnStatus:true — hand back the exit code.
                    return scanExitCode
                }
                return ''
            }
            shCommands << arg.toString()
            return null
        }
        def dir(String d, Closure c) { c() }
        def pwd(Map opts) { '/workspace@tmp' }
        def fileExists(String f) { files.containsKey(f) }
        def readFile(String f) { files[f] }
        def writeFile(Map opts) { files[opts.file.toString()] = opts.text.toString() }
        def println(def s) { printed << s.toString() }
        def publishHTML(Map target) { published << target.target }
        def catchError(Map opts, Closure c) {
            // Like Jenkins: mark and continue.
            catchErrors << opts
            try { c() } catch (Exception ignored) { }
        }
        def trivy(Map opts) { return opts }
        def recordIssues(Map opts) { published << opts }
    }

    def newEvent(FakeScript script) {
        def event = new Event()
        event.script = script
        event.version = '1.2.3'
        return event
    }

    List trivyRuns(FakeScript script) {
        return script.shCommands.findAll { it.contains('aquasecurity/trivy') }
    }

    def "[TrivyPlugin] skips when no containerImage is defined"() {
        given:
            def script = new FakeScript()
            def plugin = new TrivyPlugin()

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            assert script.shCommands == []
            assert script.printed.any { it.contains('no containerImage') }
    }

    def "[TrivyPlugin] mounts a per-job cache volume so the vulnerability DB persists between builds"() {
        given:
            def script = new FakeScript()
            def plugin = new TrivyPlugin([containerImage: 'repo/app', report: 'html'])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            def runs = trivyRuns(script)
            assert runs.size() == 1
            assert runs[0].contains('-v jpipe-trivy-cache-myjob:/root/.cache/trivy')
    }

    def "[TrivyPlugin] an explicit cacheVolume name is used as-is"() {
        given:
            def script = new FakeScript()
            def plugin = new TrivyPlugin([containerImage: 'repo/app', cacheVolume: 'shared-cache'])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script)[0].contains('-v shared-cache:/root/.cache/trivy')
    }

    def "[TrivyPlugin] cacheVolume '' disables the cache mount"() {
        given:
            def script = new FakeScript()
            def plugin = new TrivyPlugin([containerImage: 'repo/app', cacheVolume: ''])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            def runs = trivyRuns(script)
            assert runs.size() == 1
            assert !runs[0].contains(':/root/.cache/trivy')
    }

    def "[TrivyPlugin] scans an image once and records a marker with the scan outcome"() {
        given:
            def script = new FakeScript()
            def plugin = new TrivyPlugin([containerImage: 'repo/app', report: 'html'])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script).size() == 1
            def markers = script.files.findAll { k, v -> k.startsWith('.trivy-scanned-') }
            assert markers.size() == 1
            assert markers.values()[0] == '.trivy-report-repo_app|ok'
            assert script.published.size() == 1
            assert script.published[0].reportName == 'Trivy - app'
    }

    def "[TrivyPlugin] skips the scan of an identical image and reuses the first report"() {
        given:
            def script = new FakeScript()
            def first = new TrivyPlugin([containerImage: 'repo/app', report: 'html'])
            def mirror = new TrivyPlugin([containerImage: 'repo/app-mirror', report: 'html'])

        when:
            first.doRunImageScan(newEvent(script))
            mirror.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script).size() == 1
            assert script.printed.any { it.contains('identical image') }
            assert script.shCommands.any { it.contains("cp -r '.trivy-report-repo_app/.' '.trivy-report-repo_app-mirror/'") }
            assert script.published.size() == 2
            assert script.published[1].reportName == 'Trivy - app-mirror'
    }

    def "[TrivyPlugin] scans again when the second instance has a different scan configuration"() {
        given:
            def script = new FakeScript()
            def relaxed = new TrivyPlugin([containerImage: 'repo/app', severity: ['LOW']])
            def strictGate = new TrivyPlugin([containerImage: 'repo/app-mirror', severity: ['CRITICAL']])

        when:
            relaxed.doRunImageScan(newEvent(script))
            strictGate.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script).size() == 2
    }

    def "[TrivyPlugin] scans again when the report format differs"() {
        given:
            def script = new FakeScript()
            def table = new TrivyPlugin([containerImage: 'repo/app', report: 'table'])
            def html = new TrivyPlugin([containerImage: 'repo/app-mirror', report: 'html'])

        when:
            table.doRunImageScan(newEvent(script))
            html.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script).size() == 2
            assert script.published.size() == 1
    }

    def "[TrivyPlugin] scans both images when their image IDs differ"() {
        given:
            def script = new FakeScript()
            def first = new TrivyPlugin([containerImage: 'repo/app'])
            def other = new TrivyPlugin([containerImage: 'repo/other'])

        when:
            first.doRunImageScan(newEvent(script))
            script.imageId = 'sha256:def456'
            other.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script).size() == 2
    }

    def "[TrivyPlugin] distinct images sharing a basename get distinct report dirs"() {
        given:
            def script = new FakeScript()
            def first = new TrivyPlugin([containerImage: 'repo/app', report: 'html'])
            def other = new TrivyPlugin([containerImage: 'other/app', report: 'html'])

        when:
            first.doRunImageScan(newEvent(script))
            script.imageId = 'sha256:def456'
            other.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script).size() == 2
            assert trivyRuns(script)[0].contains('.trivy-report-repo_app:/report')
            assert trivyRuns(script)[1].contains('.trivy-report-other_app:/report')
    }

    def "[TrivyPlugin] skipDuplicates false always scans"() {
        given:
            def script = new FakeScript()
            def first = new TrivyPlugin([containerImage: 'repo/app', skipDuplicates: false])
            def mirror = new TrivyPlugin([containerImage: 'repo/app-mirror', skipDuplicates: false])

        when:
            first.doRunImageScan(newEvent(script))
            mirror.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script).size() == 2
            assert !script.shCommands.any { it.contains('docker inspect') }
    }

    def "[TrivyPlugin] falls back to a plain scan when the image ID cannot be resolved"() {
        given:
            def script = new FakeScript()
            script.inspectFails = true
            def plugin = new TrivyPlugin([containerImage: 'repo/app'])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script).size() == 1
            assert !script.files.keySet().any { it.startsWith('.trivy-scanned-') }
            assert script.printed.any { it.contains('could not resolve') }
    }

    def "[TrivyPlugin] allowFailure swallows a failing scan, publishes, and records the failed verdict"() {
        given:
            def script = new FakeScript()
            script.scanExitCode = 2  // vulnerabilities found
            def plugin = new TrivyPlugin([containerImage: 'repo/app', report: 'html', allowFailure: true])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            noExceptionThrown()
            assert script.catchErrors.size() == 1
            assert script.published.size() == 1
            def markers = script.files.findAll { k, v -> k.startsWith('.trivy-scanned-') }
            assert markers.values()[0] == '.trivy-report-repo_app|failed'
    }

    def "[TrivyPlugin] a failing scan without allowFailure propagates"() {
        given:
            def script = new FakeScript()
            script.scanExitCode = 2  // vulnerabilities found
            def plugin = new TrivyPlugin([containerImage: 'repo/app'])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            thrown(RuntimeException)
    }

    def "[TrivyPlugin] a skipped duplicate of a failed scan re-signals the failure"() {
        given:
            def script = new FakeScript()
            script.scanExitCode = 2  // vulnerabilities found
            def first = new TrivyPlugin([containerImage: 'repo/app', report: 'html', allowFailure: true])
            def mirror = new TrivyPlugin([containerImage: 'repo/app-mirror', report: 'html', allowFailure: true])

        when:
            first.doRunImageScan(newEvent(script))
            mirror.doRunImageScan(newEvent(script))

        then:
            noExceptionThrown()
            assert trivyRuns(script).size() == 1
            assert script.catchErrors.size() == 2
            assert script.published.size() == 2
    }

    def "[TrivyPlugin] a strict duplicate of a failed scan fails hard without allowFailure"() {
        given:
            def script = new FakeScript()
            script.scanExitCode = 2  // vulnerabilities found
            def first = new TrivyPlugin([containerImage: 'repo/app', report: 'html', allowFailure: true])
            def strictGate = new TrivyPlugin([containerImage: 'repo/app-mirror', report: 'html', allowFailure: false])

        when:
            first.doRunImageScan(newEvent(script))
            strictGate.doRunImageScan(newEvent(script))

        then:
            thrown(Exception)
            assert trivyRuns(script).size() == 1
    }

    def "[TrivyPlugin] vulnerabilities use a distinct exit code so operational errors can be told apart"() {
        given:
            def script = new FakeScript()
            def plugin = new TrivyPlugin([containerImage: 'repo/app'])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script)[0].contains('--exit-code=2')
    }

    def "[TrivyPlugin] an operational scan error fails the build even with allowFailure"() {
        given:
            def script = new FakeScript()
            script.scanExitCode = 1  // operational error (e.g. cache DB lock), not a vuln finding
            def plugin = new TrivyPlugin([containerImage: 'repo/app', report: 'html', allowFailure: true])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            // allowFailure only tolerates vulnerability findings, never a broken
            // scan: the error propagates and is not swallowed as UNSTABLE.
            thrown(RuntimeException)
            assert script.catchErrors.isEmpty()
            // No marker is written, so a retry re-scans instead of reusing a
            // transient failure verdict.
            assert !script.files.keySet().any { it.startsWith('.trivy-scanned-') }
    }
}
