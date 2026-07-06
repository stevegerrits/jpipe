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
        Map env = [BUILD_TAG: 'jenkins-job-42']
        String imageId = 'sha256:abc123'
        boolean inspectFails = false
        boolean scanFails = false

        def sh(def arg) {
            if (arg instanceof Map) {
                shCommands << arg.script.toString()
                if (arg.script.toString().contains('docker inspect')) {
                    if (inspectFails) {
                        throw new RuntimeException('no such image')
                    }
                    return imageId + '\n'
                }
                return ''
            }
            shCommands << arg.toString()
            if (arg.toString().contains('aquasecurity/trivy') && scanFails) {
                throw new RuntimeException('script returned exit code 1')
            }
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

    def "[TrivyPlugin] mounts the cache volume so the vulnerability DB persists between scans"() {
        given:
            def script = new FakeScript()
            def plugin = new TrivyPlugin([containerImage: 'repo/app', report: 'html'])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            def runs = trivyRuns(script)
            assert runs.size() == 1
            assert runs[0].contains('-v jpipe-trivy-cache:/root/.cache/trivy')
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

    def "[TrivyPlugin] scans an image once and records a marker for the build"() {
        given:
            def script = new FakeScript()
            def plugin = new TrivyPlugin([containerImage: 'repo/app', report: 'html'])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            assert trivyRuns(script).size() == 1
            assert script.files.keySet().any { it.startsWith('.trivy-scanned-') }
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
            assert script.shCommands.any { it.contains("cp -r '.trivy-report-app/.' '.trivy-report-app-mirror/'") }
            assert script.published.size() == 2
            assert script.published[1].reportName == 'Trivy - app-mirror'
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

    def "[TrivyPlugin] allowFailure swallows a failing scan and still publishes"() {
        given:
            def script = new FakeScript()
            script.scanFails = true
            def plugin = new TrivyPlugin([containerImage: 'repo/app', report: 'html', allowFailure: true])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            noExceptionThrown()
            assert script.published.size() == 1
    }

    def "[TrivyPlugin] a failing scan without allowFailure propagates"() {
        given:
            def script = new FakeScript()
            script.scanFails = true
            def plugin = new TrivyPlugin([containerImage: 'repo/app'])

        when:
            plugin.doRunImageScan(newEvent(script))

        then:
            thrown(RuntimeException)
    }
}
