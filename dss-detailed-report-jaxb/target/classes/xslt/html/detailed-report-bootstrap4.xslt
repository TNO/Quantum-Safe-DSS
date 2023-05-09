<?xml version="1.0" encoding="UTF-8" ?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:dss="http://dss.esig.europa.eu/validation/detailed-report">

	<xsl:output method="html" encoding="utf-8" indent="yes" omit-xml-declaration="yes" />

    <xsl:template match="/dss:DetailedReport">
    	<div>
			<xsl:attribute name="id">detailed-report-card</xsl:attribute>
    		<xsl:attribute name="class">card</xsl:attribute>
	   		<div>
	   			<xsl:attribute name="class">card-header bg-primary d-flex</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseDR</xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
				<div>
					<xsl:attribute name="class">align-self-center</xsl:attribute>
					Validation
				</div>
		    </div>
		    <div>
				<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
		        <xsl:attribute name="id">collapseDR</xsl:attribute>
		        
		    	<xsl:comment>Generated by DSS v.5.12.RC1</xsl:comment>
		    	
				<xsl:apply-templates select="dss:Certificate"/>
				<xsl:apply-templates select="dss:BasicBuildingBlocks[@Type='CERTIFICATE']"/>

				<xsl:apply-templates select="dss:Signature"/>
				<xsl:apply-templates select="dss:Timestamp"/>
				<xsl:apply-templates select="dss:BasicBuildingBlocks[@Type='SIGNATURE']"/>
				<xsl:apply-templates select="dss:BasicBuildingBlocks[@Type='COUNTER_SIGNATURE']"/>
				<xsl:apply-templates select="dss:BasicBuildingBlocks[@Type='TIMESTAMP']"/>
				<xsl:apply-templates select="dss:BasicBuildingBlocks[@Type='REVOCATION']"/>
				
				<xsl:apply-templates select="dss:TLAnalysis" />
			</div>
	    </div>
	    		
    </xsl:template>

	<xsl:template match="dss:Signature">
		<div>
			<xsl:attribute name="class">card mb-2 mb-sm-3</xsl:attribute>
			<div>
				<xsl:attribute name="class">card-header bg-primary</xsl:attribute>
				<xsl:attribute name="data-target">#collapseSignatureValidationData<xsl:value-of select="@Id"/></xsl:attribute>
				<xsl:attribute name="data-toggle">collapse</xsl:attribute>
				
				<xsl:call-template name="badge-conclusion">
					<xsl:with-param name="Conclusion" select="dss:Conclusion" />
					<xsl:with-param name="AdditionalClass" select="' float-right ml-2'" />
				</xsl:call-template>
				
				<xsl:if test="@CounterSignature = 'true'">
					<span>
			        	<xsl:attribute name="class">badge badge-info float-right</xsl:attribute>
						Counter-signature
		        	</span>
				</xsl:if>

				<span>Signature <xsl:value-of select="@Id"/></span>
				<i>
					<xsl:attribute name="class">id-copy fa fa-clipboard btn btn-outline-light cursor-pointer text-light border-0 p-2 ml-1 mr-1</xsl:attribute>
					<xsl:attribute name="data-id"><xsl:value-of select="@Id"/></xsl:attribute>
					<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
					<xsl:attribute name="data-placement">right</xsl:attribute>
					<xsl:attribute name="data-success-text">Id copied successfully!</xsl:attribute>
					<xsl:attribute name="title">Copy Id to clipboard</xsl:attribute>
				</i>
			</div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
				<div>
					<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
					<xsl:attribute name="id">collapseSignatureValidationData<xsl:value-of select="@Id"/></xsl:attribute>
					<xsl:apply-templates select="dss:ValidationProcessBasicSignature" />
					<xsl:apply-templates select="dss:Timestamp" />
					<xsl:apply-templates select="dss:ValidationProcessLongTermData" />
					<xsl:apply-templates select="dss:ValidationProcessArchivalData" />
   					
   					<xsl:apply-templates select="dss:ValidationSignatureQualification"/>
				</div>
			</xsl:if>
		</div>
	</xsl:template>
	
	<xsl:template match="dss:Timestamp">
		<div>
			<xsl:attribute name="class">card mb-2 mb-sm-3</xsl:attribute>
			<div>
				<xsl:attribute name="class">card-header</xsl:attribute>
				<xsl:attribute name="data-target">#collapseTimestamp<xsl:value-of select="@Id"/></xsl:attribute>
				<xsl:attribute name="data-toggle">collapse</xsl:attribute>
				
				<xsl:call-template name="badge-conclusion">
					<xsl:with-param name="Conclusion" select="dss:ValidationProcessTimestamp/dss:Conclusion" />
					<xsl:with-param name="AdditionalClass" select="' float-right ml-2'" />
				</xsl:call-template>

				<span>Timestamp <xsl:value-of select="@Id"/></span>
				<i>
					<xsl:attribute name="class">id-copy fa fa-clipboard btn btn-outline-light cursor-pointer text-dark border-0 p-2 ml-1 mr-1</xsl:attribute>
					<xsl:attribute name="data-id"><xsl:value-of select="@Id"/></xsl:attribute>
					<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
					<xsl:attribute name="data-placement">right</xsl:attribute>
					<xsl:attribute name="data-success-text">Id copied successfully!</xsl:attribute>
					<xsl:attribute name="title">Copy Id to clipboard</xsl:attribute>
				</i>
			</div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
				<div>
					<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
					<xsl:attribute name="id">collapseTimestamp<xsl:value-of select="@Id"/></xsl:attribute>
   					<xsl:apply-templates select="dss:ValidationProcessTimestamp"/>
   					<xsl:apply-templates select="dss:ValidationTimestampQualification"/>
				</div>
			</xsl:if>
		</div>
	</xsl:template>
	
	<xsl:template match="dss:BasicBuildingBlocks">    
       <div>
       		<xsl:if test="@Id != ''">
       			<xsl:attribute name="id"><xsl:value-of select="@Id"/></xsl:attribute>
       		</xsl:if>
	   		<xsl:attribute name="class">card mb-2 mb-sm-3</xsl:attribute>
	   		<div>
	   			<xsl:attribute name="class">card-header bg-primary</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseBasicBuildingBlocks<xsl:value-of select="@Id"/></xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>

				<span>Basic Building Blocks <br/><xsl:value-of select="@Type"/> (Id = <xsl:value-of select="@Id"/>)</span>
				<i>
					<xsl:attribute name="class">id-copy fa fa-clipboard btn btn-outline-light cursor-pointer text-light border-0 p-2 ml-1 mr-1</xsl:attribute>
					<xsl:attribute name="data-id"><xsl:value-of select="@Id"/></xsl:attribute>
					<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
					<xsl:attribute name="data-placement">right</xsl:attribute>
					<xsl:attribute name="data-success-text">Id copied successfully!</xsl:attribute>
					<xsl:attribute name="title">Copy Id to clipboard</xsl:attribute>
				</i>
	        </div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
				<xsl:variable name="PSV" select="dss:PSV" />
				<xsl:variable name="SubXCV" select="dss:XCV/dss:SubXCV" />
				<xsl:variable name="CRS" select="dss:VTS/dss:CRS" />
	    		<div>
	    			<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
		        	<xsl:attribute name="id">collapseBasicBuildingBlocks<xsl:value-of select="@Id"/></xsl:attribute>
					
					<xsl:apply-templates select="dss:FC" />
					<xsl:apply-templates select="dss:ISC" />
					<xsl:apply-templates select="dss:VCI" />
					<xsl:apply-templates select="dss:XCV" />
					<xsl:apply-templates select="dss:CV" />
					<xsl:apply-templates select="dss:SAV" />

    				<xsl:if test="$PSV != ''">
						<hr />
					</xsl:if>
					<xsl:apply-templates select="dss:PSV" />
					<xsl:apply-templates select="dss:PSV_CRS" />
					<xsl:apply-templates select="dss:PCV" />
					<xsl:apply-templates select="dss:VTS" />

					<xsl:if test="$SubXCV != ''">
						<hr />
					</xsl:if>
					<xsl:apply-templates select="dss:XCV/dss:SubXCV" />

					<xsl:if test="$CRS != ''">
						<hr />
					</xsl:if>
					<xsl:apply-templates select="dss:VTS/dss:CRS" />
	    		</div>
	   		</xsl:if>
	   	</div>
    </xsl:template>

	<xsl:template match="dss:ValidationProcessBasicSignature|dss:ValidationProcessLongTermData|dss:ValidationProcessArchivalData|dss:Certificate">
		<div>
			<xsl:attribute name="class">card mb-2 mb-sm-3</xsl:attribute>
    		<div>
				<xsl:attribute name="class">card-header</xsl:attribute>
				<xsl:attribute name="data-target">#collapse<xsl:value-of select="name(.)"/><xsl:value-of select="../@Id"/></xsl:attribute>
				<xsl:attribute name="data-toggle">collapse</xsl:attribute>

				<xsl:call-template name="badge-conclusion">
					<xsl:with-param name="Conclusion" select="dss:Conclusion" />
					<xsl:with-param name="AdditionalClass" select="' float-right'" />
				</xsl:call-template>
		        
	 			<xsl:value-of select="concat(@Title, ' ')"/>
				
				<xsl:if test="dss:ProofOfExistence/dss:Time">
					<i>
						<xsl:attribute name="class">constraint-tooltip fa fa-clock-o</xsl:attribute>
						<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
						<xsl:attribute name="data-placement">top</xsl:attribute>
						<xsl:attribute name="title">Best signature time : <xsl:call-template name="formatdate"><xsl:with-param name="DateTimeStr" select="dss:ProofOfExistence/dss:Time"/></xsl:call-template></xsl:attribute>
	       			</i>
					<span class="constraint-text d-none">(Best signature time : <xsl:call-template name="formatdate"><xsl:with-param name="DateTimeStr" select="dss:ProofOfExistence/dss:Time"/></xsl:call-template>)</span>
       			</xsl:if>
       			
			</div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
	    		<div>
	    			<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
		        	<xsl:attribute name="id">collapse<xsl:value-of select="name(.)"/><xsl:value-of select="../@Id"/></xsl:attribute>
		        	<xsl:apply-templates/>
	    		</div>
	    	</xsl:if>
		</div>
	</xsl:template>

	<xsl:template match="dss:ValidationProcessTimestamp">
   		<div>
   			<xsl:attribute name="class">card mb-2 mb-sm-3</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">card-header</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseTimestampValidationData<xsl:value-of select="../@Id"/></xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
       			
				<xsl:call-template name="badge-conclusion">
					<xsl:with-param name="Conclusion" select="dss:Conclusion" />
					<xsl:with-param name="AdditionalClass" select="' float-right'" />
				</xsl:call-template>
    			
	 			<xsl:value-of select="@Title"/>
	 			
	 			<br />
	 			
	 			<xsl:value-of select="concat(@Type, ' ')"/>
		       
				<i>
					<xsl:attribute name="class">constraint-tooltip fa fa-clock-o</xsl:attribute>
					<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
					<xsl:attribute name="data-placement">top</xsl:attribute>
					<xsl:attribute name="title">Production time : <xsl:call-template name="formatdate"><xsl:with-param name="DateTimeStr" select="@ProductionTime"/></xsl:call-template></xsl:attribute>
				</i>
				<span class="constraint-text d-none">(Production time : <xsl:call-template name="formatdate"><xsl:with-param name="DateTimeStr" select="@ProductionTime"/></xsl:call-template>)</span>
	        </div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
	    		<div>
	    			<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
		        	<xsl:attribute name="id">collapseTimestampValidationData<xsl:value-of select="../@Id"/></xsl:attribute>
		        	<xsl:apply-templates/>
	    		</div>
	    	</xsl:if>
    	</div>
    </xsl:template>
    
    <xsl:template match="dss:TLAnalysis">
 		<div>
	  		<xsl:if test="@Id != ''">
	  			<xsl:attribute name="id"><xsl:value-of select="@Id"/></xsl:attribute>
	  		</xsl:if>
 			<xsl:attribute name="class">card mb-2 mb-sm-3</xsl:attribute>
	   		<div>
	   			<xsl:attribute name="class">card-header</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseTL<xsl:value-of select="@CountryCode"/></xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
		       	
				<xsl:call-template name="badge-conclusion">
					<xsl:with-param name="Conclusion" select="dss:Conclusion" />
					<xsl:with-param name="AdditionalClass" select="' float-right'" />
				</xsl:call-template>

				<span><xsl:value-of select="@Title"/></span>

				<xsl:if test="@Id != ''">
					<i>
						<xsl:attribute name="class">id-copy fa fa-clipboard btn btn-outline-light cursor-pointer text-dark border-0 p-2 ml-1 mr-1</xsl:attribute>
						<xsl:attribute name="data-id"><xsl:value-of select="@Id"/></xsl:attribute>
						<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
						<xsl:attribute name="data-placement">right</xsl:attribute>
						<xsl:attribute name="data-success-text">Id copied successfully!</xsl:attribute>
						<xsl:attribute name="title">Copy Id to clipboard</xsl:attribute>
					</i>
				</xsl:if>
	        </div>
			<xsl:if test="count(child::*[name(.)!='Conclusion']) &gt; 0">
	    		<div>
	    			<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
		        	<xsl:attribute name="id">collapseTL<xsl:value-of select="@CountryCode"/></xsl:attribute>
		        	<xsl:apply-templates/>
	    		</div>
	    	</xsl:if>
	   	</div>
    </xsl:template>
    
    <xsl:template match="dss:ValidationSignatureQualification">
   		<div>
   			<xsl:attribute name="class">card</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">card-header</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseSigAnalysis<xsl:value-of select="@Id"/></xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
		        
		        <span>
					<xsl:attribute name="class">badge badge-secondary float-right</xsl:attribute>
					<xsl:value-of select="@SignatureQualification"/>	       			
       			</span>
		        
	       		<xsl:value-of select="@Title"/>
	        </div>
    		<div>
    			<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
	        	<xsl:attribute name="id">collapseSigAnalysis<xsl:value-of select="@Id"/></xsl:attribute>
	        	<xsl:apply-templates/>
    		</div>
   		</div>
    </xsl:template>
    
    <xsl:template match="dss:ValidationTimestampQualification">
   		<div>
   			<xsl:attribute name="class">card</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">card-header</xsl:attribute>
	    		<xsl:attribute name="data-target">#collapseTstAnalysis<xsl:value-of select="@Id"/></xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
		       	
		        <span>
					<xsl:attribute name="class">badge badge-secondary float-right</xsl:attribute>
					<xsl:value-of select="@TimestampQualification"/>	       			
       			</span>
		        
	       		<xsl:value-of select="@Title"/>
	        </div>
    		<div>
    			<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
	        	<xsl:attribute name="id">collapseTstAnalysis<xsl:value-of select="@Id"/></xsl:attribute>
	        	<xsl:apply-templates/>
    		</div>
   		</div>
    </xsl:template>
    
    <xsl:template match="dss:ValidationCertificateQualification">
   		<div>
   			<xsl:attribute name="class">card mt-3</xsl:attribute>
    		<div>
    			<xsl:attribute name="class">card-header</xsl:attribute>
	    		<xsl:attribute name="data-target">#cert-qual-<xsl:value-of select="generate-id(.)"/></xsl:attribute>
		       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
		        
		        <span>
					<xsl:attribute name="class">badge badge-secondary float-right</xsl:attribute>
					<xsl:value-of select="@CertificateQualification"/>	       			
       			</span>
		        
	 			<xsl:value-of select="concat(@Title, ' ')"/>
	       		
				<i>
					<xsl:attribute name="class">constraint-tooltip fa fa-clock-o</xsl:attribute>
					<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
					<xsl:attribute name="data-placement">top</xsl:attribute>
					<xsl:attribute name="title"><xsl:call-template name="formatdate"><xsl:with-param name="DateTimeStr" select="@DateTime"/></xsl:call-template></xsl:attribute>
       			</i>
				<span class="constraint-text d-none">(<xsl:call-template name="formatdate"><xsl:with-param name="DateTimeStr" select="@DateTime"/></xsl:call-template>)</span>
	 			<xsl:if test="@Id">
	       			<br />
					<span><xsl:value-of select="concat('Id = ', @Id)"/></span>
					<i>
						<xsl:attribute name="class">id-copy fa fa-clipboard btn btn-outline-light cursor-pointer text-dark border-0 p-2 ml-1 mr-1</xsl:attribute>
						<xsl:attribute name="data-id"><xsl:value-of select="@Id"/></xsl:attribute>
						<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
						<xsl:attribute name="data-placement">right</xsl:attribute>
						<xsl:attribute name="data-success-text">Id copied successfully!</xsl:attribute>
						<xsl:attribute name="title">Copy Id to clipboard</xsl:attribute>
					</i>
	        	</xsl:if>
	        </div>
    		<div>
    			<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
	        	<xsl:attribute name="id">cert-qual-<xsl:value-of select="generate-id(.)"/></xsl:attribute>
	        	<xsl:apply-templates/>
    		</div>
   		</div>
    </xsl:template>

    <xsl:template name="badge-conclusion">
        <xsl:param name="Conclusion"/>
        <xsl:param name="AdditionalClass"/>
        
        <xsl:variable name="indicationText" select="$Conclusion/dss:Indication"/>
        <xsl:variable name="indicationCssClass">
        	<xsl:choose>
				<xsl:when test="$indicationText='TOTAL_PASSED'">badge-success</xsl:when>
				<xsl:when test="$indicationText='PASSED'">badge-success</xsl:when>
				<xsl:when test="$indicationText='INDETERMINATE'">badge-warning</xsl:when>
				<xsl:when test="$indicationText='FAILED'">badge-danger</xsl:when>
				<xsl:when test="$indicationText='TOTAL_FAILED'">badge-danger</xsl:when>
				<xsl:otherwise>badge-secondary</xsl:otherwise>
			</xsl:choose>
        </xsl:variable>
        
       	<xsl:choose>
      		<xsl:when test="string-length($Conclusion/dss:SubIndication) &gt; 0">
				<xsl:variable name="semanticText" select="//dss:Semantic[contains(@Key,$Conclusion/dss:SubIndication)]"/>
		        <div>
		        	<xsl:attribute name="class">badge <xsl:value-of select="$indicationCssClass" /> <xsl:value-of select="$AdditionalClass" /></xsl:attribute>
		        	
					<xsl:if test="string-length($semanticText) &gt; 0">
						<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
						<xsl:attribute name="data-placement">right</xsl:attribute>
						<xsl:attribute name="title"><xsl:value-of select="$semanticText" /></xsl:attribute>
					</xsl:if>
		        	
		        	<xsl:value-of select="$Conclusion/dss:SubIndication"/>
	        	</div>
			</xsl:when>
			<xsl:otherwise>
				<xsl:variable name="semanticText" select="//dss:Semantic[contains(@Key,$Conclusion/dss:Indication)]"/>
       			<div>
		        	<xsl:attribute name="class">badge <xsl:value-of select="$indicationCssClass" /> <xsl:value-of select="$AdditionalClass" /></xsl:attribute>
		        	
					<xsl:if test="string-length($semanticText) &gt; 0">
						<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
						<xsl:attribute name="data-placement">right</xsl:attribute>
						<xsl:attribute name="title"><xsl:value-of select="$semanticText" /></xsl:attribute>
					</xsl:if>
					
		        	<xsl:value-of select="$Conclusion/dss:Indication"/>
		        </div>
        	</xsl:otherwise>
        </xsl:choose>
    </xsl:template>
	
    <xsl:template match="dss:FC|dss:ISC|dss:VCI|dss:CV|dss:SAV|dss:XCV|dss:PSV|dss:PSV_CRS|dss:PCV|dss:VTS">
		<div>
       		<xsl:attribute name="id"><xsl:value-of select="../@Id"/>-<xsl:value-of select="name()"/></xsl:attribute>
			<xsl:attribute name="class">row mt-1 pl-1 pl-sm-0 pt-1 pt-sm-0</xsl:attribute>
			<div>
				<xsl:attribute name="class">col</xsl:attribute>
				<strong>
					<xsl:value-of select="@Title"/> :
				</strong>

				<xsl:call-template name="badge-conclusion">
					<xsl:with-param name="Conclusion" select="dss:Conclusion" />
					<!-- AdditionalClass is empty -->
				</xsl:call-template>
			</div>
		</div>
		<xsl:apply-templates select="dss:Constraint" />
    </xsl:template>

	<xsl:template match="dss:SubXCV|dss:CRS|dss:RAC|dss:RFC">
    	<div>
	        <xsl:variable name="parentId">
	        	<xsl:choose>
					<xsl:when test="name()='SubXCV'" ><xsl:value-of select="../../@Id"/></xsl:when>
					<xsl:when test="name()='VTS'" ><xsl:value-of select="../../@Id"/></xsl:when>
					<xsl:when test="name()='RAC'" ><xsl:value-of select="concat(../@Id, '-', ../../../../@Id)"/></xsl:when>
					<xsl:when test="name(..)='ValidationProcessLongTermData'" ><xsl:value-of select="../../@Id"/></xsl:when>
					<xsl:otherwise><xsl:value-of select="concat(../@Id, '-', ../../../@Id)"/></xsl:otherwise>
	        	</xsl:choose>
	        </xsl:variable>
    		<xsl:variable name="currentId" select="concat(name(), '-', @Id, '-', $parentId)"/>
       		<xsl:attribute name="id"><xsl:value-of select="$currentId"/></xsl:attribute>
    		<div>
    			<xsl:attribute name="class">card mt-3</xsl:attribute>
	    		<div>
		    		<xsl:attribute name="data-target"><xsl:value-of select="concat('#collapse-', name(..), '-', $currentId)"/></xsl:attribute>
			       	<xsl:attribute name="data-toggle">collapse</xsl:attribute>
	    			<xsl:choose>
      					<xsl:when test="@TrustAnchor = 'true'">
	    					<xsl:attribute name="class">card-header border-bottom-0</xsl:attribute>
	    				</xsl:when>
	    				<xsl:otherwise>
	    					<xsl:attribute name="class">card-header</xsl:attribute>
	    				</xsl:otherwise>
	    			</xsl:choose>

					<div>
						<xsl:attribute name="class">constraint-tooltip float-right p-0 p-sm-2</xsl:attribute>
						<xsl:choose>
							<xsl:when test="@TrustAnchor = 'true'">
								<i>
									<xsl:attribute name="class">constraint-tooltip fa fa-certificate ml-2</xsl:attribute>
									<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
									<xsl:attribute name="data-placement">top</xsl:attribute>
									<xsl:attribute name="title">Trust Anchor</xsl:attribute>
								</i>
							</xsl:when>
							<xsl:otherwise>
								<xsl:call-template name="badge-conclusion">
									<xsl:with-param name="Conclusion" select="dss:Conclusion" />
									<xsl:with-param name="AdditionalClass" select="' float-right ml-2'" />
								</xsl:call-template>
							</xsl:otherwise>
						</xsl:choose>

						<xsl:if test="@SelfSigned = 'true'">
							<i>
								<xsl:attribute name="class">constraint-tooltip fa fa-user-circle ml-2</xsl:attribute>
								<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
								<xsl:attribute name="data-placement">top</xsl:attribute>
								<xsl:attribute name="title">Self-signed</xsl:attribute>
							</i>
						</xsl:if>

						<xsl:if test="dss:CrossCertificate">
							<i>
								<xsl:attribute name="class">constraint-tooltip fa fa-link ml-2</xsl:attribute>
								<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
								<xsl:attribute name="data-placement">top</xsl:attribute>
								<xsl:attribute name="title">Cross-Certification: <xsl:value-of select="dss:CrossCertificate"/></xsl:attribute>
							</i>
						</xsl:if>

						<xsl:if test="dss:EquivalentCertificate">
							<i>
								<xsl:attribute name="class">constraint-tooltip fa fa-refresh ml-2</xsl:attribute>
								<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
								<xsl:attribute name="data-placement">top</xsl:attribute>
								<xsl:attribute name="title">Equivalent certification: <xsl:value-of select="dss:EquivalentCertificate"/></xsl:attribute>
							</i>
						</xsl:if>
					</div>

					<div>
						<xsl:attribute name="class">float-lg-left</xsl:attribute>
						<xsl:value-of select="@Title"/>

						<xsl:if test="@Id">
							<br />
							<span><xsl:value-of select="concat('Id = ', @Id)"/></span>
							<i>
								<xsl:attribute name="class">id-copy fa fa-clipboard btn btn-outline-light cursor-pointer text-dark border-0 p-2 ml-1 mr-1</xsl:attribute>
								<xsl:attribute name="data-id"><xsl:value-of select="@Id"/></xsl:attribute>
								<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
								<xsl:attribute name="data-placement">right</xsl:attribute>
								<xsl:attribute name="data-success-text">Id copied successfully!</xsl:attribute>
								<xsl:attribute name="title">Copy Id to clipboard</xsl:attribute>
							</i>
						</xsl:if>
					</div>

					<div>
						<xsl:attribute name="class">constraint-text col-lg-3 float-lg-right text-lg-right p-0 pl-lg-2 pr-lg-2 mt-1 mt-lg-0</xsl:attribute>
						<xsl:choose>
							<xsl:when test="@TrustAnchor = 'true'">
								<div>
									<xsl:attribute name="class">constraint-text font-weight-bolder mb-1 d-none</xsl:attribute>
									Trust Anchor
								</div>
							</xsl:when>
						</xsl:choose>

						<xsl:if test="@SelfSigned = 'true'">
							<div>
								<xsl:attribute name="class">constraint-text font-weight-bolder mb-1 d-none</xsl:attribute>
								Self-signed
							</div>
						</xsl:if>

						<xsl:if test="dss:CrossCertificate">
							<div>
								<xsl:attribute name="class">constraint-text font-weight-bolder mb-1 d-none</xsl:attribute>
								Cross-Certification: <xsl:value-of select="dss:CrossCertificate"/>
							</div>
						</xsl:if>

						<xsl:if test="dss:EquivalentCertificate">
							<div>
								<xsl:attribute name="class">constraint-text font-weight-bolder mb-1 d-none</xsl:attribute>
								Equivalent certification: <xsl:value-of select="dss:EquivalentCertificate"/>
							</div>
						</xsl:if>
					</div>


		        </div>
		        
		       	<xsl:if test="name() != 'SubXCV' or @TrustAnchor != 'true'">
		    		<div>
		    			<xsl:attribute name="class">card-body p-2 p-sm-3 collapse show</xsl:attribute>
			        	<xsl:attribute name="id"><xsl:value-of select="concat('collapse-', name(..), '-', $currentId)"/></xsl:attribute>
			        	<xsl:apply-templates/>
		    		</div>
	    		</xsl:if>
    		</div>
    	</div>
    </xsl:template>

    <xsl:template match="dss:Constraint">
	    <div>
	    	<xsl:attribute name="class">row constraint mb-1 pl-1 pl-sm-0 pt-1 pt-sm-0</xsl:attribute>
	    	<div>
	    		<xsl:attribute name="class">col-md-8 col-lg-9</xsl:attribute>
				<span>
					<xsl:attribute name="class">constraint-key mb-1 mb-sm-0 d-inline-block</xsl:attribute>
					<span>
						<xsl:attribute name="class">mr-2</xsl:attribute>
						<xsl:value-of select="dss:Name"/>
					</span>
					<xsl:if test="@Id">
						<xsl:variable name="BlockType" select="@BlockType"/>
						<a>
							<xsl:choose>
								<xsl:when test="$BlockType='SUB_XCV'">
									<xsl:attribute name="href">#SubXCV-<xsl:value-of select="concat(@Id, '-', ../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='CRS' and name(..)='SubXCV'">
									<xsl:attribute name="href">#CRS-<xsl:value-of select="concat(@Id, '-', ../@Id, '-', ../../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='CRS' and name(..)='RAC'">
									<xsl:attribute name="href">#CRS-<xsl:value-of select="concat(@Id, '-', ../@Id, '-', ../../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='CRS' and name(..)='VTS'">
									<xsl:attribute name="href">#CRS-<xsl:value-of select="concat(@Id, '-', ../@Id, '-', ../../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='CRS' and name(..)='ValidationProcessLongTermData'">
									<xsl:attribute name="href">#CRS-<xsl:value-of select="concat(@Id, '-', ../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='RFC' and name(..)='ValidationProcessLongTermData'">
									<xsl:attribute name="href">#RFC-<xsl:value-of select="concat(@Id, '-', ../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='RAC' and name(..)='CRS' and name(../..)='ValidationProcessLongTermData'">
									<xsl:attribute name="href">#RAC-<xsl:value-of select="concat(@Id, '-', ../@Id, '-', ../../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='RAC' and name(..)='CRS' and name(../..)='VTS'">
									<xsl:attribute name="href">#RAC-<xsl:value-of select="concat(@Id, '-', ../@Id, '-', ../../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='RAC' and name(..)='CRS'">
									<xsl:attribute name="href">#RAC-<xsl:value-of select="concat(@Id, '-', ../@Id, '-', ../../../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='RAC' and name(..)='PSV_CRS'">
									<xsl:attribute name="href">#RAC-<xsl:value-of select="concat(@Id, '-', ../@Id, '-', ../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='RFC'">
									<xsl:attribute name="href">#RFC-<xsl:value-of select="concat(@Id, '-', ../@Id, '-', ../../../@Id)"/></xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='PSV_CRS'">
									<xsl:attribute name="href">#<xsl:value-of select="../../@Id"/>-PSV_CRS</xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='PCV'">
									<xsl:attribute name="href">#<xsl:value-of select="@Id"/>-PCV</xsl:attribute>
								</xsl:when>
								<xsl:when test="$BlockType='VTS'">
									<xsl:attribute name="href">#<xsl:value-of select="@Id"/>-VTS</xsl:attribute>
								</xsl:when>
								<xsl:otherwise>
									<xsl:attribute name="href">#<xsl:value-of select="@Id"/></xsl:attribute>
								</xsl:otherwise>
							</xsl:choose>
							<xsl:attribute name="title">Details</xsl:attribute>
							<xsl:attribute name="class">mr-1 mr-sm-2 mb-1 mb-sm-0</xsl:attribute>
							<i>
								<xsl:attribute name="class">fa fa-arrow-circle-right</xsl:attribute>
							</i>
						</a>
					</xsl:if>
				</span>
				<xsl:if test="dss:AdditionalInfo">
					<span>
						<xsl:attribute name="class">constraint-text text-muted mr-1 mb-1 mb-sm-0 d-none</xsl:attribute>
						<xsl:value-of select="dss:AdditionalInfo" />
					</span>
				</xsl:if>
	    	</div>
	    	<div>
	    		<xsl:attribute name="class">col-md-4 col-lg-3 d-sm-flex pt-0 pt-sm-1</xsl:attribute>
	        	<xsl:variable name="statusText" select="dss:Status"/>
				<xsl:variable name="iconCssClass">
					<xsl:choose>
						<xsl:when test="$statusText='OK'">fa-check-circle</xsl:when>
						<xsl:when test="$statusText='NOT OK'">fa-times-circle</xsl:when>
						<xsl:when test="$statusText='WARNING'">fa-exclamation-circle</xsl:when>
						<xsl:when test="$statusText='INFORMATION'">fa-info-circle</xsl:when>
						<xsl:when test="$statusText='IGNORED'">fa-eye-slash</xsl:when>
					</xsl:choose>
				</xsl:variable>
				<xsl:variable name="colorCssClass">
					<xsl:choose>
						<xsl:when test="$statusText='OK'">text-success</xsl:when>
						<xsl:when test="$statusText='NOT OK'">text-danger</xsl:when>
						<xsl:when test="$statusText='WARNING'">text-warning</xsl:when>
						<xsl:when test="$statusText='INFORMATION'">text-info</xsl:when>
						<xsl:when test="$statusText='IGNORED'">text-muted</xsl:when>
					</xsl:choose>
				</xsl:variable>
				<xsl:variable name="textTitle">
					<xsl:choose>
						<xsl:when test="$statusText='OK'"><xsl:value-of select="$statusText" /></xsl:when>
						<xsl:when test="$statusText='NOT OK'"><xsl:value-of select="$statusText" /> : <xsl:value-of select="dss:Error" /></xsl:when>
						<xsl:when test="$statusText='WARNING'"><xsl:value-of select="$statusText" /> : <xsl:value-of select="dss:Warning" /></xsl:when>
						<xsl:when test="$statusText='INFORMATION'"><xsl:value-of select="$statusText" /> : <xsl:value-of select="dss:Info" /></xsl:when>
						<xsl:when test="$statusText='IGNORED'"><xsl:value-of select="$statusText" /> : The check is skipped by the validation policy</xsl:when>
						<xsl:otherwise><xsl:value-of select="$statusText" /></xsl:otherwise>
					</xsl:choose>
				</xsl:variable>
				<i>
					<xsl:attribute name="class">constraint-tooltip <xsl:value-of select="$colorCssClass" /> fa <xsl:value-of select="$iconCssClass" /> mr-2 ml-0 ml-md-3 ml-lg-5</xsl:attribute>
					<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
					<xsl:attribute name="data-placement">left</xsl:attribute>
					<xsl:attribute name="title"><xsl:value-of select="$textTitle" /></xsl:attribute>
				</i>
				<span>
					<xsl:attribute name="class">constraint-text <xsl:value-of select="$colorCssClass" /> d-none</xsl:attribute>
					<xsl:value-of select="$textTitle" />
				</span>
	    		
	    		<xsl:if test="dss:AdditionalInfo">
		    		<i>
		    			<xsl:attribute name="class">constraint-tooltip fa fa-plus-circle text-info</xsl:attribute>
						<xsl:attribute name="data-toggle">tooltip</xsl:attribute>
						<xsl:attribute name="data-placement">right</xsl:attribute>
						<xsl:attribute name="title"><xsl:value-of select="dss:AdditionalInfo" /></xsl:attribute>
		    		</i>
	    		</xsl:if>
	    	</div>
	    </div>
    </xsl:template>

	<xsl:template match="*">
		<xsl:comment>
			Ignored tag:
			<xsl:value-of select="name()" />
		</xsl:comment>
	</xsl:template>

	<xsl:template name="formatdate">
		<xsl:param name="DateTimeStr" />

		<xsl:variable name="date">
			<xsl:value-of select="substring-before($DateTimeStr,'T')" />
		</xsl:variable>

		<xsl:variable name="after-T">
			<xsl:value-of select="substring-after($DateTimeStr,'T')" />
		</xsl:variable>

		<xsl:variable name="time">
			<xsl:value-of select="substring-before($after-T,'Z')" />
		</xsl:variable>

		<xsl:choose>
			<xsl:when test="string-length($date) &gt; 0 and string-length($time) &gt; 0">
				<xsl:value-of select="concat($date,' ', $time, ' (UTC)')" />
			</xsl:when>
			<xsl:when test="string-length($date) &gt; 0">
				<xsl:value-of select="$date" />
			</xsl:when>
			<xsl:when test="string-length($time) &gt; 0">
				<xsl:value-of select="$time" />
			</xsl:when>
			<xsl:otherwise>-</xsl:otherwise>
		</xsl:choose>
	</xsl:template>

</xsl:stylesheet>