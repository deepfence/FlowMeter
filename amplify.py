import pandas as pd
import numpy as np

COL_NOISE = [
    "flowDuration",
    "flowLength",
    "fwdFlowLength",
    "bwdFlowLength",
    "packetSizeTotal",
    "packetSizeMean",
    "packetSizeStd",
    "packetSizeMin",
    "packetSizeMax",
    "fwdPacketSizeTotal",
    "bwdPacketSizeTotal",
    "fwdPacketSizeMean",
    "bwdPacketSizeMean",
    "fwdPacketSizeStd",
    "bwdPacketSizeStd",
    "fwdPacketSizeMin",
    "bwdPacketSizeMin",
    "fwdPacketSizeMax",
    "bwdPacketSizeMax",
    "IATMean",
    "IATStd",
    "IATMin",
    "IATMax",
    "fwdIATTotal",
    "bwdIATTotal",
    "fwdIATMean",
    "bwdIATMean",
    "fwdIATStd",
    "bwdIATStd",
    "fwdIATMin",
    "bwdIATMin",
    "fwdIATMax",
    "bwdIATMax",
]


def cols_append(col1, col2):
    return col1 + "-" + str(col2)


def amplifiedDF(df, ifAmplify, scaleAmplify, coeffOfVariation):
    """Amplify data (coefficent of variation)

    Args:
        df (pandas.core.frame.DataFrame): Input dataframe
        ifAmplify (bool): Whether amplification should happen
        scaleAmplify (int): Scale of amplification
        coeffOfVariation (float): Coefficient of variation. Useful in addition of Gaussian noise.

    Returns:
        pandas.core.frame.DataFrame: Dataframe with larger number of rows.
    """
    pd_cp = df.copy(deep=True)

    if ifAmplify:
        pd_amplify = pd.concat([pd_cp] * scaleAmplify)
        pd_amplify["rowNum"] = np.arange(len(pd_amplify))
        pd_amplify["fiveTupleOrig"] = pd_amplify["fiveTuple"]
        pd_amplify["fiveTuple"] = pd_amplify.apply(
            lambda x: cols_append(col1=x["fiveTuple"], col2=x["rowNum"]), axis=1
        )

        for i in range(len(pd_amplify["fiveTupleOrig"].unique())):
            fiveTuple = pd_amplify["fiveTupleOrig"].unique()[i]

            pd_ch = pd_amplify[pd_amplify["fiveTupleOrig"] == fiveTuple]
            for col in COL_NOISE:
                ## Coefficient of variation = sigma / mu
                mu, sigma = 0, pd_ch[col].mean() * coeffOfVariation
                noise = np.random.normal(mu, sigma, (pd_ch.shape[0],))

                pd_ch[col] = pd_ch[col] + noise

            if i == 0:
                pd_comb = pd_ch

            else:
                pd_comb = pd.concat([pd_comb, pd_ch])

        return pd_comb
