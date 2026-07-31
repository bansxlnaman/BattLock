function run_integration()
%RUN_INTEGRATION  BattLock co-simulation driver (Option A).
%
%   1. Runs the Simulink model for all 6 attack modes and exports the CAN
%      frame stream to frames.csv.
%   2. Invokes the real BattLock Python verification stack
%      (integration/verify_frames.py), which judges every frame with the
%      actual crypto/counters/protocol code and writes frames_verified.csv.
%   3. Plots Python verdicts (auth / replay / injection) per mode and
%      writes an agreement report.
%
%   Outputs (in the current directory):
%       frames.csv           - raw CAN frames from Simulink
%       frames_verified.csv  - Python verdicts per frame + model comparison
%       integration_plot.png - per-mode Python verdict plots
%       integration_report.csv
%
%   Usage:
%       cd <repo>
%       run_integration

    repo = fileparts(fileparts(mfilename('fullpath')));   % repo root
    simdir = fullfile(repo, 'simulink');

    % ---------- Step 1: export frames from Simulink -------------
    fprintf('\n[1/3] Exporting CAN frames from Simulink...\n');
    export_frames(simdir);   % writes simulink/frames.csv

    % ---------- Step 2: verify frames with real Python code ------
    fprintf('\n[2/3] Verifying frames with real BattLock Python code...\n');
    cmd = sprintf('py -3.11 "%s" "%s" "%s"', ...
        fullfile(repo, 'integration', 'verify_frames.py'), ...
        fullfile(simdir, 'frames.csv'), ...
        fullfile(simdir, 'frames_verified.csv'));
    [status, output] = system(cmd);
    fprintf('%s\n', output);
    if status ~= 0
        error('Python verification failed (exit %d)', status);
    end

    % ---------- Step 3: plot + report ----------------------------
    fprintf('\n[3/3] Generating integration plot and report...\n');
    make_integration_plots(fullfile(simdir, 'frames_verified.csv'), ...
        fullfile(simdir, 'integration_plot.png'), ...
        fullfile(simdir, 'integration_report.csv'));
    fprintf('DONE. See simulink/integration_plot.png and simulink/integration_report.csv\n');
end
