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
        // time than the scan itself. Set to '' to disable the mount.
        this.cacheVolume = opts.get('cacheVolume', 'jpipe-trivy-cache');
        // Pipelines that publish the same built image under several names would
        // scan identical bits once per name. When enabled, images whose docker
        // image ID was already scanned in this build reuse the first report.
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
            String priorReportDir = ''
            if (marker != '' && event.script.fileExists(marker)) {
                priorReportDir = event.script.readFile(marker).trim()
            }

            if (priorReportDir != '') {
                event.script.println("Skipping Trivy scan for ${image}: an identical image (same image ID) was already scanned in this build")
                if (this.report == 'html' || this.report == 'json') {
                    event.script.sh "mkdir -p ${reportDir} && if [ -d '${priorReportDir}' ]; then cp -r '${priorReportDir}/.' '${reportDir}/'; fi"
                }
            } else {
                this.runScan(event, image, reportDir)
                if (marker != '') {
                    event.script.writeFile(file: marker, text: reportDir)
                }
            }

            this.publishReport(event, imgName, reportDir)
        }
    }

    private void runScan(Event event, String image, String reportDir) {
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

        String cacheMount = this.cacheVolume != '' ? "-v ${this.cacheVolume}:/root/.cache/trivy" : ''

        try {
            event.script.sh """
                docker run \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    -v \$(pwd)/${reportDir}:/report \
                    ${cacheMount} \
                    ghcr.io/aquasecurity/trivy:${this.trivyVersion} \
                    image ${args.join(' ')} ${image}
            """
        } catch (Exception e) {
            if (this.allowFailure) {
                event.script.catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    throw e
                }
            } else {
                throw e
            }
        }
    }

    // A per-build, per-image-ID marker file in the shared tmp workspace. Two
    // plugin instances that resolve to the same image ID (identical layers
    // published under different names) produce the same marker, so the second
    // one can tell a scan already happened. Returns '' when duplicate
    // detection is disabled or the image ID cannot be resolved.
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
        // Markers from previous builds are stale; clean them up as we go.
        event.script.sh "find . -maxdepth 1 -name '.trivy-scanned-*' -mtime +1 -delete || true"
        String buildTag = event.script.env.BUILD_TAG ?: 'build'
        String marker = ".trivy-scanned-${buildTag}-${event.version}-${imageId}"
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
