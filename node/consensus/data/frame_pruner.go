package data

import "go.uber.org/zap"

func (e *DataClockConsensusEngine) pruneFrames(maxFrame uint64) error {
	e.logger.Info("pruning frames", zap.Uint64("max_frame_to_prune", maxFrame))
	err := e.clockStore.DeleteDataClockFrameRange(e.filter, 1, maxFrame)
	if err != nil {
		e.logger.Error("failed to prune frames", zap.Error(err))
		return err
	}
	return nil
}
