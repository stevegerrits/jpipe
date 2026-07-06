package io.stenic.jpipe.plugin

import io.stenic.jpipe.event.Event

class TrivyPlugin extends Plugin {

    private Boolean allowFailure;
    private String containerImage;
    private Integer eventWeight;
    private String extraFlags;
    private Boolean ignoreUnfixed;
    private List severity;
    private String trivyVersion;
    private String report;
    private String cacheVolume;
    private Boolean skipDuplicates;

    TrivyPlugin(Map opts = [:]) {
        this.report = opts.get('report', 'table');
        this.allowFailure = opts.get('allowFailure', false);
        this.trivyVersion = opts.get('trivyVersion', 'latest');
        this.containerImage = opts.get('containerImage', '');
        this.extraFlags = opts.get('extraFlags', '');
        this.ignoreUnfixed = opts.get('ignoreUnfixed', true);
        this.severity = opts.get('severity', ['HIGH', 'CRITICAL', 'MEDIUM', 'LOW', 'UNKNOWN']);
        this.eventWeight = opts.get('eventWeight', 20);
        // Named docker volume holding the Trivy cache (vulnerability DB). The DB
        // is re-downloaded on every scan otherwise, which typically costs more
        // time than the scan itself. Defaults to a per-job volume (null =>
        // "jpipe-trivy-cache-<job>"): trivy's cache DB takes an exclusive file
        // lock, so one cluster-wide volume would let concurrent builds of
        // unrelated jobs contend ("database is locked"). Scans within one build
        // run sequentially and are safe. Set to '' to disable the mount, or to
        // a fixed name to deliberately share a volume.
        this.cacheVolume = opts.get('cacheVolume', null);
        // Pipelines that publish the same built image under several names would
        // scan identical bits once per name. When enabled, images whose docker
        // image ID was already scanned in this build WITH THE SAME scan
        // configuration reuse the first scan's report and verdict.
        this.skipDuplicates = opts.get('skipDuplicates', true);
    }

    public Map getSubscribedEvents() {
        return [
            "${Event.TEST}": [
                [{ event -> this.doRunImageScan(event) }, this.eventWeight],
            ],
        ]
    }

    public void doRunImageScan(Event event) {
        if (this.containerImage == '') {
            event.script.println("Skipping TrivyPlugin: no containerImage defined")
            return
        }

        String image = "${this.containerImage}:${event.version}"
        String imgName = this.containerImage.split('/').last()
        String reportDir = ".trivy-report-${imgName}"

        event.script.dir(event.script.pwd(tmp: true)) {
            String marker = this.duplicateMarker(event, image)
            String markerText = ''
            if (marker != '' && event.script.fileExists(marker)) {
                markerText = event.script.readFile(marker).trim()
            }

            if (markerText != '') {
                String priorReportDir = markerText.split(/\|/)[0]
                Boolean priorFailed = markerText.endsWith('|failed')
                event.script.println("Skipping Trivy scan for ${image}: an identical image (same image ID) was already scanned with the same configuration in this build")
                if (this.report == 'html' || this.report == 'json') {
                    event.script.sh "mkdir -p '${reportDir}' && if [ -d '${priorReportDir}' ]; then cp -r '${priorReportDir}/.' '${reportDir}/'; fi"
                }
                if (priorFailed) {
                    // Keep the verdict truthful on the skip path: the same
                    // image failed its scan earlier in this build, so this
                    // instance must fail (or go UNSTABLE) the same way.
                    this.handleScanFailure(event, new Exception("Trivy reported issues for an identical image scanned earlier in this build (${image})"))
                }
            } else {
                Boolean scanFailed = false
                try {
                    this.execScan(event, image, reportDir)
                } catch (Exception e) {
                    scanFailed = true
                    this.handleScanFailure(event, e)
                }
                if (marker != '') {
                    event.script.writeFile(file: marker, text: "${reportDir}|${scanFailed ? 'failed' : 'ok'}")
                }
            }

            this.publishReport(event, imgName, reportDir)
        }
    }

    private void execScan(Event event, String image, String reportDir) {
        List args = [
            '--no-progress',
            '--exit-code=1',
            "--severity ${this.severity.join(',')}",
        ]
        if (this.report == 'html') {
            args.add('--format template  --template "@contrib/html.tpl" -o /report/report.html')
        } else if (this.report == 'json') {
            args.add('--format json -o /report/report.json')
        }
        if (this.ignoreUnfixed == true) {
            args.add('--ignore-unfixed')
        }
        args.add(this.extraFlags)

        String volume = this.resolveCacheVolume(event)
        String cacheMount = volume != '' ? "-v ${volume}:/root/.cache/trivy" : ''

        event.script.sh """
            docker run \
                -v /var/run/docker.sock:/var/run/docker.sock \
                -v \$(pwd)/${reportDir}:/report \
                ${cacheMount} \
                ghcr.io/aquasecurity/trivy:${this.trivyVersion} \
                image ${args.join(' ')} ${image}
        """
    }

    // Note: a non-zero exit can mean "vulnerabilities found" but also any other
    // scan error (e.g. cache contention); trivy's exit code does not
    // distinguish them, so neither can allowFailure.
    private void handleScanFailure(Event event, Exception e) {
        if (this.allowFailure) {
            event.script.catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                throw e
            }
        } else {
            throw e
        }
    }

    private String resolveCacheVolume(Event event) {
        if (this.cacheVolume == null) {
            String job = (event.script.env.JOB_BASE_NAME ?: 'default').toString().replaceAll(/[^A-Za-z0-9._-]/, '_')
            return "jpipe-trivy-cache-${job}"
        }
        return this.cacheVolume
    }

    // A per-build marker file in the shared tmp workspace, keyed by image ID
    // AND the scan-relevant configuration. Two plugin instances only share a
    // marker when they would run the exact same scan on the exact same bits —
    // a stricter or differently-formatted second instance still scans.
    // Returns '' when duplicate detection is disabled or the image ID cannot
    // be resolved.
    private String duplicateMarker(Event event, String image) {
        if (!this.skipDuplicates) {
            return ''
        }
        String imageId = ''
        try {
            imageId = event.script.sh(script: "docker inspect -f '{{.Id}}' ${image}", returnStdout: true).trim()
        } catch (Exception e) {
            event.script.println("TrivyPlugin: could not resolve the image ID of ${image}; scanning without duplicate detection")
            return ''
        }
        // Pure hygiene, not correctness: markers embed the unique BUILD_TAG so
        // stale ones can never match a later build — this only stops them from
        // accumulating in the tmp workspace.
        event.script.sh "find . -maxdepth 1 -name '.trivy-scanned-*' -mtime +1 -delete || true"
        String buildTag = event.script.env.BUILD_TAG ?: 'build'
        String config = "${this.severity.join(',')}|${this.ignoreUnfixed}|${this.extraFlags}|${this.report}|${this.trivyVersion}"
        String marker = ".trivy-scanned-${buildTag}-${event.version}-${imageId}-${config.hashCode()}"
        return marker.replaceAll(/[^A-Za-z0-9._-]/, '_')
    }

    private void publishReport(Event event, String imgName, String reportDir) {
        if (this.report == 'html') {
            event.script.publishHTML(target: [
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: reportDir,
                reportFiles: 'report.html',
                reportName: "Trivy - ${imgName}",
            ])
        } else if (this.report == 'json') {
            event.script.recordIssues tool: event.script.trivy(
                pattern: "${reportDir}/report.json",
                reportEncoding: 'UTF-8'
            )
        }
    }
}
